#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#include "../headers/hooks.h"


int print_packet(struct tcp_packet *packet)
{
    if (packet == NULL) return -1;

    printk(KERN_INFO "TCP message received!\n");
    printk(KERN_INFO "Source\t\t%pI4:%d\n", packet->src_addr, packet->src_port);
    printk(KERN_INFO "Destination\t%pI4:%d\n", packet->dest_addr, packet->dest_port);
    printk(KERN_INFO "%s\n", packet->data);
    printk(KERN_INFO "--------------------\n");

    return 0;
}

unsigned int netfilter_hook(void *priv, struct sk_buff *sk_buf, const struct nf_hook_state *state)
{
    struct iphdr* ip_header;    // IP header structure
    struct tcphdr* tcp_header;  // TCP header structure
    struct tcp_packet packet;          // Pointer to packet data

    if (!sk_buf) return NF_ACCEPT;

    ip_header = ip_hdr(sk_buf);

    // Check if the packet is TCP
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(sk_buf);

        packet.src_addr = &ip_header->saddr;
        packet.dest_addr = &ip_header->daddr;
        packet.src_port = ntohs(tcp_header->source);
        packet.dest_port = ntohs(tcp_header->dest);


        if (sk_buf->len > (ip_header->ihl * 4 + tcp_header->doff * 4)) {
            packet.data = (unsigned char*)((unsigned char*) tcp_header + (tcp_header->doff * 4));
        }

        // Print packet info
        print_packet(&packet);
    }


    return NF_ACCEPT;
}


MODULE_LICENSE("GPL");