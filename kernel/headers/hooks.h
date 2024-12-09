#ifndef HOOKS_H 
#define HOOKS_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>


struct tcp_packet {
    unsigned int* src_addr;
    unsigned int* dest_addr;
    int src_port;
    int dest_port;
    char* timestamp;
    char* data;
};

extern unsigned int netfilter_hook(void* priv, struct sk_buff* sk_buf, const struct nf_hook_state* state);
int print_packet(struct tcp_packet* packet);

#endif