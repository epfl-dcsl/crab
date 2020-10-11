/*
 * MIT License
 *
 * Copyright (c) 2019-2021 Ecole Polytechnique Federale Lausanne (EPFL)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <stdint.h>
#include <strings.h>

#include <rte_config.h>
#include <rte_tcp.h>

#include <dp/api.h>
#include <dp/core.h>

#include <net/utils.h>

#define MAX_TARGETS 64
#define SYN_FLAG 0x02
#define REDIR_OPT_TYPE 0x2A

static int target_count;
static uint32_t targets[MAX_TARGETS];

static uint32_t pick_target(void)
{
	return targets[rand() % target_count];
}

static void add_redir_opt(struct ipv4_hdr *iph, struct tcp_hdr *tcph)
{
	uint8_t *options;
	int l4hlen, opt_len;
	uint32_t *orig_ip;

	l4hlen = ((tcph->data_off & 0xF0) >> 4) * 4;
	opt_len = l4hlen - sizeof(struct tcp_hdr);

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
	*orig_ip = iph->dst_addr;
	options += sizeof(uint32_t);

	// Add two nops
	*options++ = 0x01;
	*options++ = 0x01;

	// Fix header size
	tcph->data_off = (((l4hlen + 8)/4) & 0xF) << 4;
}

void router_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			   struct udp_hdr *l4h)
{
	uint32_t target, source;
	int l4hlen;
	struct tcp_hdr *tcph = (struct tcp_hdr *)l4h;

	if (tcph->tcp_flags != SYN_FLAG) {
		printf("Unknown TCP packet\n");
		rte_pktmbuf_free(pkt_buf);
		return;
	}

	add_redir_opt(iph, tcph);
	l4hlen = ((tcph->data_off & 0xF0) >> 4) * 4;
	target = pick_target();
	source = rte_be_to_cpu_32(iph->src_addr);

	// Recompute tcp checksum
	tcph->cksum = 0;
	iph->hdr_checksum = 0;
	iph->src_addr = rte_cpu_to_be_32(source);
	iph->dst_addr = rte_cpu_to_be_32(target);
	iph->total_length = rte_cpu_to_be_16(
			rte_be_to_cpu_16(iph->total_length) + 8);
	tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
	assert(tcph->cksum);

	ip_out(pkt_buf, iph, source, target, iph->time_to_live,
			iph->type_of_service, IPPROTO_TCP, l4hlen, NULL);
}

int app_init(int argc, char **argv)
{
	char *tok;

	printf("Hello L4 loadbalancer\n");
	if (argc != 2) {
		printf("Usage: ./lbl4 -l <cores> -- <ip1,ip2,...>\n");
		return -1;
	}

	// Parse targets
	tok = strtok_r(argv[1], ",", &argv[1]);
	while(tok) {
		assert(target_count < MAX_TARGETS);
		targets[target_count++] = ip_str_to_int(tok);
		printf("target %d: %s %x\n", target_count, tok, targets[target_count-1]);

		tok = strtok_r(argv[1], ",", &argv[1]);
	}

	return 0;
}

void app_main(void)
{
	do {
		net_poll();
	} while (!force_quit);
}
