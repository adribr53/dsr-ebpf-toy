#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP bpf_htons(0x0800)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} pkt_cnt SEC(".maps");


SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;

	if (eth->h_proto != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_ABORTED;

	__u64 *pkt_cnt_elem;
	pkt_cnt_elem = bpf_map_lookup_elem(&pkt_cnt, &iph->daddr);
	if (pkt_cnt_elem) {
		(*pkt_cnt_elem)++;
	} else {
		__u64 pkt_cnt_value = 1;
		bpf_map_update_elem(&pkt_cnt, &iph->daddr, &pkt_cnt_value, BPF_NOEXIST);
	}

	return XDP_PASS;
}
