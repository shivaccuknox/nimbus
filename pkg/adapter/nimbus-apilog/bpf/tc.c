//go:build ignore

#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include "helpers.h"
#include "defines.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";


struct http_hdr_t {
    unsigned char c[32];
};

// ringbuffer event map
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

#ifdef GOLANG
// golang requires the code to have type, "tc" inside the SEC
SEC("tc")
#else
SEC("ingress")
#endif
int tc_ingress(struct __sk_buff *ctx) {
	if(ctx == NULL) return TC_ACT_OK;
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
 
    struct ethhdr *l2;
    struct iphdr *l3;
    struct event *event_info;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // get L2
    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    // get L3
    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;
    
    // parse packet accordingly
    if (IS_UDP_PACKET(l3->protocol)) {
        // reserve ringbuffer
        event_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!event_info)
            return TC_ACT_OK;
        event_info->direction = DIR_INGRESS;

        // @todo maybe function pointers for abstraction?
        if (parse_udp_packet(&event_info, ctx, l3) != 0) {
            bpf_ringbuf_discard(event_info, 0);
        } else {
            bpf_ringbuf_submit(event_info, 0);
        }
    } else if (IS_TCP_PACKET(l3->protocol)) {
        // reserve ringbuffer
        event_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!event_info)
            return TC_ACT_OK;
        event_info->direction = DIR_INGRESS;

        // @todo maybe function pointers for abstraction?
        if (parse_tcp_packet(&event_info, ctx, l3) != 0) {
            bpf_ringbuf_discard(event_info, 0);
        } else {
            bpf_ringbuf_submit(event_info, 0);
        }
    }

    return TC_ACT_OK;
}

#ifdef GOLANG
// golang requires the code to have type, "tc" inside the SEC
SEC("tc")
#else
SEC("egress")
#endif
int tc_egress(struct __sk_buff *ctx) {
	if(ctx == NULL) return TC_ACT_OK;
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;

    struct ethhdr *l2;
    struct iphdr *l3;
    struct event *event_info;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // get L2
    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    // get L3
    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    // parse packet accordingly
    if (IS_UDP_PACKET(l3->protocol)) {
        // reserve ringbuffer
        event_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!event_info)
            return TC_ACT_OK;
        event_info->direction = DIR_EGRESS;

        // @todo maybe function pointers for abstraction?
        if (parse_udp_packet(&event_info, ctx, l3) != 0) {
            bpf_ringbuf_discard(event_info, 0);
        } else {
            bpf_ringbuf_submit(event_info, 0);
        }
    } else if (IS_TCP_PACKET(l3->protocol)) {
        // reserve ringbuffer
        event_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!event_info)
            return TC_ACT_OK;
        event_info->direction = DIR_EGRESS;

        // @todo maybe function pointers for abstraction?
        if (parse_tcp_packet(&event_info, ctx, l3) != 0) {
            bpf_ringbuf_discard(event_info, 0);
        } else {
            bpf_ringbuf_submit(event_info, 0);
        }
    }

    return TC_ACT_OK;
}
