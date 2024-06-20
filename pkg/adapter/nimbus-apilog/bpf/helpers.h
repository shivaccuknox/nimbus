#pragma once
#include "defines.h"
#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

#define UDP_PROTO 0x11
#define TCP_PROTO 0x06
#define SCTP_PROTO 0x84

#define IS_UDP_PACKET(protocol) ((protocol & UDP_PROTO) == UDP_PROTO)
#define IS_TCP_PACKET(protocol) ((protocol & TCP_PROTO) == TCP_PROTO)
#define IS_SCTP_PACKET(protocol) ((protocol & SCTP_PROTO) == SCTP_PROTO)

// parse_udp_packet function
static inline __attribute__((always_inline)) int parse_udp_packet(struct event **event_info, struct __sk_buff *skb, struct iphdr *l3) {
    void *data_end = (void *)(__u64)skb->data_end;
    struct udphdr *l4 = ((void *)l3) + (l3->ihl*4);
    u8 *udp_payload_offset;
    if ((void*)&l4[1] > data_end)
        return -1;

    // calculate payload offset
    udp_payload_offset = (u8 *)l4 + sizeof(struct udphdr);
    if ((void *)udp_payload_offset + 1 > data_end)
        return -1;

    // dump info
    (*event_info)->addr_pair = ((u64)l3->saddr & 0xFFFFFFFF) | (((u64)l3->daddr & 0xFFFFFFFF) << 32); // both be
    (*event_info)->port_pair = l4->source | (l4->dest << 16); // both be

    // dump UDP payload
    (*event_info)->len = data_end - (void *) udp_payload_offset;
    (*event_info)->type = TYPE_UDP;
    bpf_probe_read_kernel((*event_info)->buff, BUFF_SIZE, (void *) udp_payload_offset);

    return 0;
}

static inline __attribute__((always_inline)) int trick(u32 actual, u32 expected) {
        return expected - actual <= 0 ? 0 : expected - actual > BUFF_SIZE ? BUFF_SIZE : expected - actual;
}

// parse_tcp_packet function
static inline __attribute__((always_inline)) int parse_tcp_packet(struct event **event_info, struct __sk_buff *skb, struct iphdr *l3) {
    // get L4
    void *data_end = (void *)(__u64)skb->data_end;
    struct tcphdr *l4 = ((void *)l3) + (l3->ihl*4);
    if ((void*)&l4[1] > data_end)
        return -1;

    if (skb == NULL) 
        return -1;

    // figure out if the length of skb is actually same as skb->len
    // https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
    // some cases, we manually need to pull data from skb (non-linear)   
    u32 actual_len = (void *)(__u64) skb->data_end - (void *)(__u64) skb->data;
    
    if (skb->len > actual_len) {
        int ret = 0;
        for (u16 i = 1 ; i < 300 && ret == 0; i++) {
            // unfortunately, bpf verifier gets messed up when we use skb->len - actual_len
            // the verifier considers the value of payload as negative and rejects the program
            // refer to https://stackoverflow.com/questions/78041475/how-to-read-arbitrary-len-bytes-using-helper-bpf-skb-load-bytes
            // for more information, for now we will just do a loop that literally tries 0 to 300
            // also, bpf_skb_load_bytes will return -14 if the len failed, so this will try to detect
            // the first moment when the return value is not zero.
            // @todo: improve this.
            ret = bpf_skb_load_bytes(skb, actual_len, (*event_info)->buff, i);
            if (ret != 0 && i > 2) {
                bpf_skb_load_bytes(skb, actual_len, (*event_info)->buff, i-1);
                break;
            }
        }
    } else { // when direct packet access was available, just access them
        // calculate payload offset
        u8 *tcp_payload_offset = ((void *)l4) + (l4->doff*4);
        if ((void*)&tcp_payload_offset[1] > data_end)
            return -1;
        bpf_probe_read_kernel((*event_info)->buff, BUFF_SIZE, (void *) tcp_payload_offset);
    }

    // dump info
    (*event_info)->addr_pair = ((u64)l3->saddr & 0xFFFFFFFF) | (((u64)l3->daddr & 0xFFFFFFFF) << 32); // both be
    (*event_info)->port_pair = l4->source | (l4->dest << 16); // both be

    // dump UDP payload
    (*event_info)->len = skb->len;
    (*event_info)->type = TYPE_TCP;

    return 0;
}