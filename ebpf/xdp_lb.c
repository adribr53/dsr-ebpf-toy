#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP bpf_htons(0x0800)
#define IP4_OCTETS(a)  (a)[0], (a)[1], (a)[2], (a)[3]

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") service_dsr_ipv4 = { // fed by userspace, read by xdp
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 1024,
};

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

	// __u32 *service_dsr_cnt;
	// service_dsr_cnt = bpf_map_lookup_elem(&service_dsr_ipv4, &iph->daddr);
	// if (service_dsr_cnt) {
	// 	__u64 service_dsr_cnt_value = *service_dsr_cnt + 1;
	// 	bpf_map_update_elem(&service_dsr_ipv4, &iph->daddr, &service_dsr_cnt_value, BPF_EXIST);
	// } else {
	// 	__u64 service_dsr_cnt_value = 1;
	// 	bpf_map_update_elem(&service_dsr_ipv4, &iph->daddr, &service_dsr_cnt_value, BPF_NOEXIST);
	// }
	u32 key = 0;
	key = bpf_ntohl(iph->daddr);
	__u32 *silent = bpf_map_lookup_elem(&service_dsr_ipv4, &key);
	if (silent != NULL) {
		// set ip option
		//bpf_printk("ip is svc dsr-cap ip"  "", IP_ARG(iph->daddr));
		//bpf_printk("ip is svc dsr-cap=%u.%u.%u.%u\n",  IP4_OCTETS(&key));		
		bpf_printk("ip is svc dsr-cap=%08x\n", __builtin_bswap32((__be32)key));  /* 203.0.113.1 → 0xcb007101 style */
	} else {
		//sudo cat /sys/kernel/debug/tracing/trace_pipe
		//bpf_printk("std ip=%u.%u.%u.%u\n", IP4_OCTETS(&key));
		bpf_printk("ip=%08x\n", __builtin_bswap32((__be32)iph->daddr));  /* 203.0.113.1 → 0xcb007101 style */
	}
	return XDP_PASS;
}
