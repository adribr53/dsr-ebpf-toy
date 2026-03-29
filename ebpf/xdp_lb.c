#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP bpf_htons(0x0800)
#define IP4_OCTETS(a)  (a)[0], (a)[1], (a)[2], (a)[3]
#define IP_HDR_LEN_AFTER_OPT 28u  /* ihl==7 after +8 bytes options */

char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") service_dsr_ipv4 = { // fed by userspace, read by xdp
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 1024,
};

static __always_inline __u16 ip_checksum(struct iphdr *iph)
{
    iph->check = 0;
	
    __u32 csum = bpf_csum_diff(0, 0, (__be32 *)iph, IP_HDR_LEN_AFTER_OPT, 0);

    // fold 32 → 16
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    return ~csum;
}

/* Assumes IPv4, no VLAN. Extend eth_len if you parse 802.1Q. */

#ifndef IP_OPT_LEN
#define IP_OPT_LEN 8u
#endif

static __always_inline bool add_ip_svc_option(struct xdp_md *xdp, __be32 svc_ip_n)
{
	const __u32 opt_len = 8u;
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;

	struct ethhdr *old_eth = data;
	struct iphdr *old_iph = (void *)old_eth + sizeof(*old_eth);

	if ((void *)(old_iph + 1) > data_end || old_iph->ihl != 5)
		return false;

	if (bpf_xdp_adjust_head(xdp, -(__s32)opt_len))
		return false;

	data = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;

	struct ethhdr *new_eth = data;
	struct ethhdr *src_eth = data + opt_len;
	struct iphdr *new_iph = (void *)new_eth + sizeof(*new_eth);
	struct iphdr *src_iph = (void *)src_eth + sizeof(*src_eth);

	if ((void *)(src_iph + 1) > data_end)
		return false;

	if ((void *)new_iph + IP_HDR_LEN_AFTER_OPT > data_end)
		return false;

	*new_eth = *src_eth;
	*new_iph = *src_iph;

	__u8 *opt = (__u8 *)new_iph + sizeof(*new_iph);
	if (opt + opt_len > data_end)
		return false;

	opt[0] = 0x1e;
	opt[1] = 6;
	*(__be32 *)(opt + 2) = svc_ip_n;
	opt[6] = 0x01;
	opt[7] = 0x01;

	new_iph->ihl += 2u;
	new_iph->tot_len = bpf_htons(bpf_ntohs(new_iph->tot_len) + (__u16)opt_len);
	new_iph->check = 0;
	new_iph->check = ip_checksum(new_iph);
	
	return true;
}

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
		bool completed = add_ip_svc_option(ctx, iph->daddr);
		if (!completed) {
			bpf_printk("failed to add ip option\n");
			return XDP_ABORTED;
		} else {
			bpf_printk("successfully added ip option\n");
		}
	} else {
		//sudo cat /sys/kernel/debug/tracing/trace_pipe
		//bpf_printk("std ip=%u.%u.%u.%u\n", IP4_OCTETS(&key));
		bpf_printk("ip=%08x\n", __builtin_bswap32((__be32)iph->daddr));  /* 203.0.113.1 → 0xcb007101 style */
	}
	return XDP_PASS;
}
