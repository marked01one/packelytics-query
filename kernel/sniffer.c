#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/debugfs.h>

#include <linux/time.h>


#define MAX_LOG_SIZE (1024 * 1024)
#define LOG_FILENAME "sniffer-data"


static struct nf_hook_ops netfilter_hook_ops;

// Callback function for netfilter hook
static unsigned int hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct iphdr* ip_header;  // IP header structure
    struct tcphdr* tcp_header; // TCP header structure
    // unsigned char* user_data;  // Pointer to packet data

    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb);

    // Check if the packet is TCP
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);

        int src_port = ntohs(tcp_header->source);
        int dest_port = ntohs(tcp_header->dest);

        // Print packet info
        printk(KERN_INFO "tcp\tsrc: %pI4:%d\tdest: %pI4:%d\n", 
            &ip_header->saddr, src_port,
            &ip_header->daddr, dest_port
        );
    }


    return NF_ACCEPT;
}



static int __init sniffer_init(void) {
    netfilter_hook_ops.hook = hook_func;                  // Hook function
    netfilter_hook_ops.hooknum = NF_INET_PRE_ROUTING;     // Receive packets before routing
    netfilter_hook_ops.pf = PF_INET;                      // IPv4
    netfilter_hook_ops.priority = NF_IP_PRI_FIRST;        // High priority

    // Register the hook
    nf_register_net_hook(&init_net, &netfilter_hook_ops);
    printk(KERN_INFO "TCP Sniffer loaded\n");

    return 0;
}

static void __exit sniffer_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_hook_ops);
    printk(KERN_INFO "TCP Sniffer unloaded\n");
}


module_init(sniffer_init);
module_exit(sniffer_exit);

MODULE_LICENSE("GPL");




