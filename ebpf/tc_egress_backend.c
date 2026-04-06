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
get_key(struct __sk_buff *skb, struct flow_key *key)
{

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("get_key: fail eth+1 oob\n");
        return false;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("get_key: fail iph+1 oob\n");
        return false;
    }
    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    struct tcphdr *tcph = (void *)(iph+1);
    if ((void *)(tcph+1) > data_end) {
        bpf_printk("get_key: fail tcph+1 oob\n");
        return false;
    }
    key->src_port = tcph->dest;
    key->dst_port = tcph->source;
    key->proto = iph->protocol;
    return true;
}

static __always_inline bool
set_src_ip(struct __sk_buff *skb, __u32 *svc) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("set_src_ip: fail eth+1 oob\n");
        return false;
    }
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("set_src_ip: fail iph+1 oob\n");
        return false;
    }
    iph->saddr=*svc; // TODO no endianess drama in demo (1.1.1.1)
    iph->check = 0;
    __u16 *hdr = (__u16 *)iph;
    __u32 csum = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {  // 20 bytes = 10 x 16-bit words
        csum += hdr[i];
    }
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum += (csum >> 16);
    iph->check = ~((__u16)csum);
    bpf_printk("checksum written: %x", iph->check);
    return true;
}

static long count_cb(struct bpf_map *map, const void *key,
                     void *value, void *ctx)
{
    __u64 *cnt = ctx;
    (*cnt)++;
    return 0; // continue
}

SEC("classifier")
int tc_ingress_backend_prog(struct __sk_buff *skb) {
    struct flow_key mykey = {0};
    if (get_key(skb, &mykey)) {
        __u32 *mysvc = (__u32 *) bpf_map_lookup_elem(&flow_to_dsr, &mykey);
        if (mysvc == NULL) {
            bpf_printk("lookup_key: false\n");    
            __u64 count = 0;
            bpf_for_each_map_elem(&flow_to_dsr, count_cb, &count, 0);
            bpf_printk("[DEBUG] lookup_key cnt: %d\n", count);    
        } else {
            set_src_ip(skb, mysvc);            
        }
    } else {
        bpf_printk("get_key: false\n");
    }   
    return TC_ACT_OK;
}