#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define IP4_OCTETS(a)  (a)[0], (a)[1], (a)[2], (a)[3]
#define MAX_MAP_ENTRIES 1
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710
#define MAX_IP_HDR_LENGTH 60
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif


char LICENSE[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") service_dsr_ipv4 = { // fed by userspace, read by xdp
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 1024,
};

/* Assumes IPv4, no VLAN. Extend eth_len if you parse 802.1Q. */

#ifndef IP_OPT_LEN
#define IP_OPT_LEN 8u
#endif

#define MAX_PAYLOAD 1500

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum)
{
  int i;
#pragma unroll
  for (i = 0; i < 4; i++)
  {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(
    void *iph,
    __u64 *csum,
    __u8 hdr_len)
{
  __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
  for (int i = 0; i < hdr_len >> 1; i++)
  {
    if (i>=MAX_IP_HDR_LENGTH) {
        *csum += *next_iph_u16++;
    }
        
  }
  *csum = csum_fold_helper(*csum);
}

// __attribute__((__always_inline__)) static inline void
// ipv4_csum(void* data_start, int data_size, __u64* csum) {
//   *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
//   *csum = csum_fold_helper(*csum);
// }

__attribute__((__always_inline__)) static inline void create_v4_hdr(
    struct iphdr *iph,
    __u32 saddr,
    __u32 daddr,
    __u16 pkt_bytes,
    __u8 proto,
    __u8 ihl,
    __u32 backend_ip_n)
{
  __u64 csum = 0;
  iph->version = 4;
  iph->tot_len = bpf_htons(pkt_bytes);
  iph->ihl = ihl;
  iph->frag_off = 0;
  iph->protocol = proto;
  iph->check = 0;
  
  iph->ttl = 64;
  iph->saddr = saddr;
  iph->daddr = backend_ip_n;
  __u8 *ipoption = (__u8 *) ((struct iphdr *)iph + 1);
  *(ipoption) = 0x1e;   // option type
  *(ipoption+1)= 6;      // length  
  *(__u8 *)(ipoption+2) = (daddr >> 24) & 0xff;
  *(__u8 *)(ipoption+3) = (daddr >> 16) & 0xff;
  *(__u8 *)(ipoption+4) = (daddr >> 8)  & 0xff;
  *(__u8 *)(ipoption+5) = (daddr)       & 0xff;
  ipv4_csum_inline(iph, &csum, ihl*4);
  iph->check = csum;
}

static __always_inline bool
add_ip_svc_option(struct xdp_md *xdp, __be32 backend_ip_n)
{
    const __u32 opt_len = 8;
    // ip option add
    if (bpf_xdp_adjust_head(xdp, 0 - (int)opt_len))
    {
        return false;
    }

    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end) {
        bpf_printk("add_ip_opt: fail new_eth+1 oob\n");
        return false;
    }
    struct iphdr *new_iph = (void *)(new_eth + 1);
    if ((void *)(new_iph + 1) > data_end) {
        bpf_printk("add_ip_opt: fail new_iph+1 oob\n");
        return false;
    }
    struct ethhdr *src_eth = (void *)data + opt_len;
    if ((void *)(src_eth + 1) > data_end) {
        bpf_printk("add_ip_opt: fail src_eth+1 oob\n");
        return false;
    }
    struct iphdr *src_iph = (void *)src_eth + sizeof(*src_eth);
    if ((void *)(src_iph + 1) > data_end) {
        bpf_printk("add_ip_opt: fail src_iph+1 oob\n");
        return false;
    }
    memcpy(new_eth->h_dest, src_eth->h_dest, 6);
    if ((void *) src_eth->h_dest + 6 > data_end)
    {
        return false;
    }
    memcpy(new_eth->h_source, src_eth->h_source, 6);
    new_eth->h_proto = BE_ETH_P_IP;

    create_v4_hdr(new_iph, src_iph->saddr, src_iph->daddr, opt_len+bpf_ntohs(src_iph->tot_len), src_iph->protocol, src_iph->ihl+(opt_len/4), backend_ip_n);    
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

	if (eth->h_proto != BE_ETH_P_IP)
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
	__u32 *backend = bpf_map_lookup_elem(&service_dsr_ipv4, &key);
	if (backend != NULL) {
		// set ip option
		//bpf_printk("ip is svc dsr-cap ip"  "", IP_ARG(iph->daddr));
		//bpf_printk("ip is svc dsr-cap=%u.%u.%u.%u\n",  IP4_OCTETS(&key));		
		bpf_printk("ip is svc dsr-cap=%08x\n", __builtin_bswap32((__be32)key));  /* 203.0.113.1 → 0xcb007101 style */
		bool completed = add_ip_svc_option(ctx, bpf_htonl(*backend));
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
