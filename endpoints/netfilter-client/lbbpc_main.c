#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/inet_hashtables.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/inet_sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MARIOS KOGIAS");

MODULE_DESCRIPTION("Load Balancer ByPass Client Netfilter");
MODULE_VERSION("0.01");

#define REDIR_OPT_TYPE 0x2A

static uint32_t *find_redir_ip(struct tcphdr *tcph)
{
	uint8_t *options;
	int l4hlen, opt_len;
	uint32_t *old_ip = NULL;

	l4hlen = tcph->doff * 4;
	opt_len = l4hlen - sizeof(struct tcphdr);

	options = (uint8_t *)(tcph+1);
	// parse options here
	while(opt_len) {
		if (*options == REDIR_OPT_TYPE) {
			old_ip = (uint32_t *)(options+2);
			break;
		}
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

	return old_ip;
}

static void lbbp_handle_syn_ack(struct net *netns, struct iphdr *iph,
		struct tcphdr *tcph, int dif, int sdif)
{
	struct sock *sk;
	uint32_t *old_addr;
	struct inet_sock *isk;

	old_addr = find_redir_ip(tcph);
	if (!old_addr)
		return;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,13,16)
	sk = __inet_lookup_established(netns, &tcp_hashinfo, *old_addr,
			tcph->source, iph->daddr, ntohs(tcph->dest), dif);
#else
	sk = __inet_lookup_established(netns, &tcp_hashinfo, *old_addr,
			tcph->source, iph->daddr, ntohs(tcph->dest), dif, sdif);
#endif
	if (sk) {
		isk = (struct inet_sock *)sk;

		// unhash
		inet_unhash(sk);

		// modify
		sk->__sk_common.skc_daddr = iph->saddr;
		isk->cork.fl.u.ip4.daddr  = iph->saddr;

		// hash again
		inet_hash(sk);
	}
}

static unsigned int lbbp_in_hookfn(void *priv, struct sk_buff *skb,
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
	if (tcph->syn && tcph->ack) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,13,16)
		lbbp_handle_syn_ack(dev_net(state->in), iph, tcph, inet_iif(skb), 0);
#else
		lbbp_handle_syn_ack(dev_net(state->in), iph, tcph, inet_iif(skb),
				inet_sdif(skb));
#endif
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops lbbp_hook_ops = {
	.hook     = lbbp_in_hookfn,
	.pf       = PF_INET,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static int __init lbbp_init(void) {
	printk(KERN_INFO "Hello from crab client module!\n");
	nf_register_net_hook(&init_net, &lbbp_hook_ops);

	return 0;
}

static void __exit lbbp_exit(void) {
	printk(KERN_INFO "Bye from crab client module!\n");
	nf_unregister_net_hook(&init_net, &lbbp_hook_ops);
}

module_init(lbbp_init);
module_exit(lbbp_exit);
