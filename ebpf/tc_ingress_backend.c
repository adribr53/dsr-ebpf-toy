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
#define TC_ACT_OK 0
#define TC_ACT_SHOT -1
#define TC_ACT_REDIRECT 7
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif


char LICENSE[] SEC("license") = "GPL";

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3]; // explicit padding, BPF map keys are compared byte-for-byte
};

struct bpf_map_def SEC("maps") flow_to_dsr = { // fed by userspace, read by xdp
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct flow_key),
	.value_size  = sizeof(u32),
	.max_entries = 1024,
};

static __always_inline bool
lookup_ip_svc_option(struct __sk_buff *skb, struct flow_key *key, __u32 *svc)
{

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail eth+1 oob\n");
        return false;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail iph+1 oob\n");
        return false;
    }
    key->src_ip = iph->daddr;
    key->dst_ip = iph->saddr;
    __u8 *ipopt = (__u8 *) (iph+1);
    if ((void *)(ipopt+1) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail ip option oob\n");
        return false;
    }
    if (*ipopt != 0x1e) {
        bpf_printk("lookup_ip_svc_option: ip option isn't set\n");
        return false;
    }
    if ((void *)(ipopt+2) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail ipopt+1 oob\n");
        return false;
    }
    __u8 optLen = *(ipopt+1);
    if (optLen!=6) {
        bpf_printk("lookup_ip_svc_option: ip option len isn't std\n");
        return false;
    }
    if ((void *)(ipopt+6) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail ipopt+5 oob\n");
        return false;
    }
    __u32 svcAddr = 0;
    svcAddr |=  ((__u32)*(ipopt+2)) << 24;
    svcAddr |=  ((__u32)*(ipopt+3)) << 16;
    svcAddr |=  ((__u32)*(ipopt+4)) << 8;
    svcAddr |=  ((__u32)*(ipopt+5));
    *svc = svcAddr;
    if ((void *) (ipopt+6) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail ipopt+6 oob\n");
        return false;
    }
    struct tcphdr *tcph = (void *)(ipopt+8);
    if ((void *)(tcph+1) > data_end) {
        bpf_printk("lookup_ip_svc_option: fail tcph+1 oob\n");
        return false;
    }
    key->dst_port = tcph->dest;
    key->src_port = tcph->source;
    key->proto = iph->protocol;
    return true;
}

static __always_inline bool
remove_ip_svc_option(struct __sk_buff *skb) {
    const __u32 opt_len = 8;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *src_eth = data;
    if ((void *)(src_eth + 1) > data_end) {
        bpf_printk("remove_ip_svc_option: fail src_eth+1 oob\n");
        return false;
    }
    struct iphdr *src_iph = (void *)(src_eth + 1);    
    if (((void *)src_iph + opt_len) > data_end) {
        bpf_printk("remove_ip_svc_option: fail src_iph+1 oob\n");
        return false;
    }
    void *new_ip = (void *)src_iph + opt_len;
    if (new_ip+sizeof(struct iphdr) > data_end) {
        bpf_printk("remove_ip_svc_option: fail new_ip+sizeof(struct iphdr) oob\n");
        return false;
    }
    memcpy(new_ip, src_iph, sizeof(struct iphdr));
    void *new_eth = (void *)src_eth + opt_len;
    memcpy(new_eth, src_eth, sizeof(struct ethhdr));
    struct iphdr *new_iph = (struct iphdr *) new_ip;
    if ((void *)(new_iph+1) > data_end) {
        bpf_printk("remove_ip_svc_option: fail new_iph+1 oob\n");
        return false;
    }    
        
    new_iph->ihl = 5;
    new_iph->tot_len = bpf_htons(bpf_ntohs(new_iph->tot_len) - opt_len);
    new_iph->check = 0;
    __u16 *hdr = (__u16 *)new_iph;
    __u32 csum = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {  // 20 bytes = 10 x 16-bit words
        csum += hdr[i];
    }
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum += (csum >> 16);
    new_iph->check = ~((__u16)csum);
    bpf_printk("checksum written: %x", new_iph->check);
    if (bpf_skb_adjust_room(skb, (int)-opt_len, BPF_ADJ_ROOM_MAC, 0)) {
        return false;
    }
    return true;
}

SEC("classifier")
int tc_ingress_backend_prog(struct __sk_buff *skb) {
    __u32 mysvc = 0;
    struct flow_key mykey = {0};
    bpf_printk("lookup_ip_svc_option: starting\n");
    if (lookup_ip_svc_option(skb, &mykey, &mysvc)) {
        bpf_printk("lookup_ip_svc_option: insertion about to happen\n");
        bpf_map_update_elem(&flow_to_dsr, &mykey, &mysvc, BPF_NOEXIST);
        // TODO: remove ip option
        if (!remove_ip_svc_option(skb)) {
            bpf_printk("remove_ip_svc_option: failed\n");
        }
        bpf_printk("remove_ip_svc_option: success\n");
        bpf_printk("lookup_ip_svc_option: ended\n");
    } else {
        bpf_printk("lookup_ip_svc_option: ended\n");
    }
    return TC_ACT_OK;
}