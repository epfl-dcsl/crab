/*
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
static uint8_t toeplitz_key = 0xDE;

static uint32_t compute_toeplitz_hash(uint8_t *key, uint32_t src_addr,
		uint32_t dst_addr, uint16_t src_port, uint16_t dst_port)
{
	int i, j;
	uint8_t input[12];
	uint32_t result = 0;
	uint32_t key_part = htonl(((uint32_t *)key)[0]);

	memcpy(&input[0], &src_addr, 4);
	memcpy(&input[4], &dst_addr, 4);
	memcpy(&input[8], &src_port, 2);
	memcpy(&input[10], &dst_port, 2);

	for (i = 0; i < 12; i++) {
		for (j = 128; j; j >>= 1) {
			if (input[i] & j)
				result ^= key_part;
			key_part <<= 1;
			if (key[i + 4] & j)
				key_part |= 1;
		}
	}

	return result;
}

void router_in(struct rte_mbuf *pkt_buf, struct ipv4_hdr *iph,
			   struct udp_hdr *l4h)
{
	uint32_t target, source, hash;
	int l4len;
	struct tcp_hdr *tcph = (struct tcp_hdr *)l4h;

	hash = compute_toeplitz_hash(&toeplitz_key, htonl(iph->dst_addr),
			htonl(iph->src_addr), htons(tcph->dst_port), htons(tcph->src_port));
	target = targets[hash % target_count];

	source = rte_be_to_cpu_32(iph->src_addr);
	l4len = rte_be_to_cpu_16(iph->total_length) - sizeof(struct ipv4_hdr);

	// Recompute tcp checksum
	tcph->cksum = 0;
	iph->hdr_checksum = 0;
	iph->dst_addr = rte_cpu_to_be_32(target);
	tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);

	ip_out(pkt_buf, iph, source, target, iph->time_to_live,
			iph->type_of_service, IPPROTO_TCP, l4len, NULL);
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
