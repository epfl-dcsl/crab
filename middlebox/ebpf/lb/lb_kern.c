#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64 // max number of target servers for LB
#define REDIR_OPT_TYPE 42


struct __attribute__((packed)) eth_addr {
	unsigned char addr[ETH_ALEN];
};

struct __attribute__((packed)) redir_opt {
	__u8 type;
	__u8 size;
	__u32 ip;
	__u16 nop;
};

struct __attribute__((packed)) ipv4_psd_header {
	__u32 src_addr; /* IP address of source host. */
	__u32 dst_addr; /* IP address of destination host. */
	__u8  zero;     /* zero. */
	__u8  proto;    /* L4 protocol type. */
	__u16 len;      /* L4 length. */
};


struct bpf_map_def SEC("maps") targets_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = MAX_TARGET_COUNT,
};

struct bpf_map_def SEC("maps") macs_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct eth_addr),
	.max_entries = MAX_TARGET_COUNT,
};

struct bpf_map_def SEC("maps") targets_count = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") cpu_rr_idx = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 1,
};

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

#ifdef RAND
static __always_inline int get_target_idx_rand(void)
{
	void *count;
	int key = 0;
	__u32 idx = bpf_get_prandom_u32();

	count = bpf_map_lookup_elem(&targets_count, &key);
	if (!count)
		return idx;
	return idx % *((__u32 *)count);
}
#else
static __always_inline int get_target_idx_rr(void)
{
	void *count, *rr_idx;
	int key = 0, idx = 0;

	count = bpf_map_lookup_elem(&targets_count, &key);
	if (!count)
		return idx;
	rr_idx = bpf_map_lookup_elem(&cpu_rr_idx, &key);
	if (!rr_idx)
		return idx;
	return (*((__u32 *)rr_idx))++ % *((__u32 *)count);
}
#endif

static __always_inline int get_target(__u32 *daddr)
{
	void *target;
#ifdef RAND
	int key = get_target_idx_rand();
#else
	int key = get_target_idx_rr();
#endif

	target = bpf_map_lookup_elem(&targets_map, &key);
	if (!target)
		return -1;
	__builtin_memcpy(daddr, target, sizeof(__u32));

	return 0;
}

static __always_inline int update_macs(__u32 *dst_ip, struct ethhdr *ethh)
{
	void *target;

	__builtin_memcpy(ethh->h_source, ethh->h_dest, sizeof(struct eth_addr));
	target = bpf_map_lookup_elem(&macs_map, dst_ip);
	if (!target)
		return -1;
	__builtin_memcpy(ethh->h_dest, target, sizeof(struct eth_addr));

	return 0;
}

static __always_inline int handle_syn(struct xdp_md *ctx, struct ethhdr *ethh,
		struct iphdr *iph, struct tcphdr *tcph)
{

	int i;
	struct ethhdr ethh_old;
	struct iphdr iph_old;
	struct tcphdr tcph_old;
	__u32 size = sizeof(struct iphdr);
	void *data_end = (void *)(long)ctx->data_end;
	void *ptr;
	__u32 *opt;
	struct redir_opt ropt;
	struct ipv4_psd_header psdh;
	__u32 csum;

	(void)parse_ip6hdr;
	(void)parse_icmp6hdr;
	(void)parse_icmphdr;
	(void)parse_icmphdr_common;
	(void)parse_udphdr;

	/* Filter */
	// FIXME

	/* Copy old headers */
	__builtin_memcpy(&ethh_old, ethh, sizeof(ethh_old));
	__builtin_memcpy(&iph_old, iph, sizeof(iph_old));
	__builtin_memcpy(&tcph_old, tcph, sizeof(tcph_old));

	/* Adjust the packet size for the extra options */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct redir_opt)))
		return XDP_ABORTED;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	ethh = (void *)(long)ctx->data;

	if (ethh + 1 > data_end)
		return XDP_ABORTED;
	__builtin_memcpy(ethh, &ethh_old, sizeof(ethh_old));

	iph = (struct iphdr *)(ethh+1);
	if (iph + 1 > data_end)
		return XDP_ABORTED;
	__builtin_memcpy(iph, &iph_old, sizeof(iph_old));

	/* Fix ip total len */
	iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + sizeof(struct redir_opt));

	/* Change destination address */
	if (get_target(&iph->daddr))
		return XDP_ABORTED;
	if (update_macs(&iph->daddr, ethh))
		return XDP_ABORTED;

	/* Fix IP checksum */
	iph->check = 0;
	iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, size, 0));

	/* TCP HDR */
	tcph = (struct tcphdr *)(iph+1);
	if (tcph + 1 > data_end)
		return XDP_ABORTED;
	__builtin_memcpy(tcph, &tcph_old, sizeof(tcph_old));
	tcph->doff = tcph->doff + sizeof(struct redir_opt) / 4;

	/* Fix new TCP options */
	ptr = (void *)(tcph+1);
	if (ptr + sizeof(struct redir_opt) > data_end)
		return XDP_ABORTED;
	ropt.type = REDIR_OPT_TYPE;
	ropt.size = 6;
	ropt.ip = iph_old.daddr;
	ropt.nop = 0x0101;
	__builtin_memcpy(ptr, &ropt, sizeof(struct redir_opt));

	/* Fix TCP CSUM */
	tcph->check = 0;
	csum = bpf_csum_diff(0, 0, (__be32 *)tcph,
			sizeof(struct tcphdr) + sizeof(struct redir_opt), 0);
	opt = ptr + sizeof(struct redir_opt);
	#pragma unroll
	for (i=0;i<MAX_OPT_WORDS;i++) {
		if (opt + 1 > data_end)
			break;

		csum = bpf_csum_diff(0, 0, opt, sizeof(__u32), csum);
		opt++;
	}
	csum = csum_reduce_helper(csum);
	psdh.src_addr = iph->saddr;
	psdh.dst_addr = iph->daddr;
	psdh.zero = 0;
	psdh.proto = IPPROTO_TCP;
	psdh.len = bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr));
	csum = bpf_csum_diff(0, 0, (__be32*)&psdh, sizeof(struct ipv4_psd_header),
			csum);

	tcph->check = ~csum_reduce_helper(csum);

	return XDP_TX;
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 action = XDP_PASS; /* Default action */
	struct hdr_cursor nh;
	int nh_type;
	int ip_type;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &ethh);
	if (nh_type != bpf_htons(ETH_P_IP))
		goto OUT;
	ip_type = parse_iphdr(&nh, data_end, &iph);
	if (ip_type != IPPROTO_TCP)
		goto OUT;
	if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
		action = XDP_ABORTED;
		goto OUT;
	}
	if ((tcph->ack) || (tcph->rst))
		goto OUT;
	if (tcph->syn)
		action = handle_syn(ctx, ethh, iph, tcph);

OUT:
	return action;
}

char _license[] SEC("license") = "GPL";
