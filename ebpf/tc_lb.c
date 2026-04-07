#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT -1
#define TC_ACT_REDIRECT 7
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

__attribute__((__always_inline__)) static inline void create_v4_hdr(
    struct iphdr *iph,
    __u32 saddr,
    __u32 daddr,
    __u16 pkt_bytes,
    __u8 proto,
    __u8 ihl,
    __u32 backend_ip_n,
    void *data_end)
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
  if ((void *)(ipoption+6) > data_end) {
    bpf_printk("lookup_ip_svc_option: fail ipopt+5 oob\n");
    return;
  }
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
add_ip_svc_option(struct __sk_buff *skb, __be32 backend_ip_n)
{
    const __u32 opt_len = 8;
    // ip option add
    if (bpf_skb_adjust_room(skb, (int)opt_len, BPF_ADJ_ROOM_NET, 0)) {
      return false;
    }      
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("add_ip_opt: fail new_eth+1 oob\n");
        return false;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("add_ip_opt: fail new_iph+1 oob\n");
        return false;
    }    

    create_v4_hdr(iph, iph->saddr, iph->daddr, opt_len+bpf_ntohs(iph->tot_len), iph->protocol, iph->ihl+(opt_len/4), backend_ip_n, data_end);    
    return true;
}

SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_SHOT;

	if (eth->h_proto != BE_ETH_P_IP)
		return TC_ACT_OK;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_SHOT;
	
	u32 key = 0;
	key = bpf_ntohl(iph->daddr);
	__u32 *backend = bpf_map_lookup_elem(&service_dsr_ipv4, &key); // get backend for svc ip
	if (backend != NULL) {
		// set ip option
    bpf_printk("ip is svc dsr-cap=%08x\n", __builtin_bswap32((__be32)key));  /* 203.0.113.1 → 0xcb007101 style */
		bool completed = add_ip_svc_option(skb, bpf_htonl(*backend));
		if (!completed) {
			bpf_printk("failed to add ip option\n");
			return TC_ACT_SHOT;
		} else {
			bpf_printk("successfully added ip option\n");
		}
	} else {
		bpf_printk("ip=%08x\n", __builtin_bswap32((__be32)iph->daddr));  /* 203.0.113.1 → 0xcb007101 style */
    return TC_ACT_OK;
  }
  __u32 ifindex = 10232; // TODO, set from sudo ip netns exec dsr-lb cat /sys/class/net/srv0/ifindex;
  return bpf_redirect_neigh(ifindex, NULL, 0, 0);
}
