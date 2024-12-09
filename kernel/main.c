#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/debugfs.h>

#include <linux/time.h>

#include "headers/hooks.h"


// Initialize the netfilter hook
static const struct nf_hook_ops netfilter_hook_ops = {
    .hook = netfilter_hook,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST
};


static const struct file_operations packet_fops;


static int __init sniffer_init(void) {
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




