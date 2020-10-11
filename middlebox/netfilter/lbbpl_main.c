#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/inet_hashtables.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_sock.h>

#include "lbbp.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MARIOS KOGIAS");

MODULE_DESCRIPTION("Load Balancer ByPass Server Netfilter");
MODULE_VERSION("0.01");

#define REDIR_OPT_TYPE 0x2A

static struct lbbpl_cfg_params cfg = {0};
static DEFINE_PER_CPU(uint8_t, rr_idx);

static int match(struct iphdr *iph, struct tcphdr *tcph)
{
	if ((iph->daddr == cfg.vip) && (tcph->dest == cfg.port))
		return 1;

	return 0;
}

static uint32_t pick_target_rr(void)
{
	uint8_t idx;

	idx = get_cpu_var(rr_idx)++;
	put_cpu_var(rr_idx);

	return cfg.targets[idx % cfg.target_count];
}

static uint32_t pick_target_rand(void)
{
	uint8_t idx;

	get_random_bytes(&idx, 1);

	return cfg.targets[idx % cfg.target_count];
}

static void pick_target(struct iphdr *iph)
{
	if (cfg.lbt == LB_RR)
		iph->daddr = pick_target_rr();
	else if (cfg.lbt == LB_RAND)
		iph->daddr = pick_target_rand();
}

static void add_redir_opt(struct iphdr *iph, struct tcphdr *tcph)
{
	uint8_t *options;
	int l4hlen, opt_len;
	uint32_t *orig_ip;

	l4hlen = tcph->doff * 4;
	opt_len = l4hlen - sizeof(struct tcphdr);

	options = (uint8_t *)(tcph+1);
	// parse options here
	while(opt_len) {
		if (*options < 2) {
			options++;
			opt_len--;
			if (*options == 0)
				break;
			else if (*options == 1)
				continue;
		} else {
			opt_len -= *(options+1);
			options += *(options+1);
		}
	}
	*options++ = REDIR_OPT_TYPE;
	*options++ = 6; // 1 type, 1 len, 4 ip
	orig_ip = (uint32_t *)options;
	*orig_ip = iph->daddr;
	options += sizeof(uint32_t);

	// Add two nops
	*options++ = 0x01;
	*options++ = 0x01;

	// Fix header sizes
	tcph->doff = (((l4hlen + 8)/4) & 0xF);
	iph->tot_len = htons(ntohs(iph->tot_len) + 8);
}

static void lbbp_handle_syn(struct sk_buff *skb, struct iphdr *iph,
		struct tcphdr *tcph)
{
	int tcplen;

	if (!cfg.target_count || !match(iph, tcph))
		return;

	add_redir_opt(iph, tcph);
	pick_target(iph);

	skb->csum_start = 0;
	skb->csum_offset = 0;
	skb->len += 8;

	// Fix IP checksum
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	skb->csum_valid = 0;
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

	// Fix TCP checksum
	if(skb_is_nonlinear(skb))
		skb_linearize(skb);
	tcplen = tcph->doff * 4;
	tcph->check = 0;
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,
			csum_partial((char *)tcph, tcplen, 0));
}

static unsigned int lbbp_out_hookfn(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct tcphdr *tcph;
	struct iphdr *iph;

	if (skb == NULL)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if(iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->syn && !tcph->ack)
		lbbp_handle_syn(skb, iph, tcph);

	return NF_ACCEPT;
}

static long lbbp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case LBBPL_CFG:
		if (copy_from_user(&cfg, argp, sizeof(struct lbbpl_cfg_params)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static struct nf_hook_ops lbbp_hook_ops = {
	.hook     = lbbp_out_hookfn,
	.pf       = PF_INET,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static const struct file_operations lbbp_fops = {
	.owner		    = THIS_MODULE,
	.unlocked_ioctl	= lbbp_ioctl,
};

static struct miscdevice lbbp_dev = {
	MISC_DYNAMIC_MINOR,
	"lbbp",
	&lbbp_fops,
};

static int __init lbbp_init(void) {
	int ret;

	printk(KERN_INFO "Hello from lbbp module!\n");
	cfg.target_count = 0;

	ret = nf_register_net_hook(&init_net, &lbbp_hook_ops);
	if (ret)
		return ret;

	ret = misc_register(&lbbp_dev);
	if (ret)
		return ret;

	return 0;
}

static void __exit lbbp_exit(void) {
	printk(KERN_INFO "Bye from lbbp module!\n");
	nf_unregister_net_hook(&init_net, &lbbp_hook_ops);
	misc_deregister(&lbbp_dev);
}

module_init(lbbp_init);
module_exit(lbbp_exit);
