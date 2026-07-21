/*
 * oplus_network_vnet.ko — Virtual Network Interface Driver
 *
 * Reverse-engineered from OPD2404 16.0.5.702 oplus_network_vnet.ko
 * Reimplemented for Linux 4.19 kernel (TB371FC 4.19.157-perf+)
 *
 * Function: Creates ovnet%d virtual interfaces that bind to physical
 * network interfaces (e.g. wlan0) and forward packets via neigh_xmit.
 * Used by OPPO Epona cross-device interconnection framework.
 *
 * Original vermagic: 6.1.68-android14-11-o-g4a4638c23eb0
 * Target vermagic:   4.19.157-perf+
 *
 * License: GPL
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/u64_stats_sync.h>
#include <net/neighbour.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/arp.h>

#define OVNET_MAX_DEVS 16
#define OVNET_MODULE_NAME "oplus_network_vnet"

/* Netlink attributes for ovnet link type */
enum {
	IFLA_OVNET_UNSPEC,
	IFLA_OVNET_BIND_IFINDEX,   /* u32: ifindex of physical dev to bind */
	__IFLA_OVNET_MAX,
};
#define IFLA_OVNET_MAX (__IFLA_OVNET_MAX - 1)

static int numvnets = 3;
module_param(numvnets, int, 0444);
MODULE_PARM_DESC(numvnets, "Number of ovnet devices");

/* ============================================================
 * Per-device private data
 * In 4.19 kernel, u64_stats_t does not exist — use plain u64
 * with struct u64_stats_sync for seqcount protection.
 * ============================================================ */
struct ovnet_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	struct u64_stats_sync syncp;
};

struct ovnet_dev {
	struct net_device *netdev;
	struct net_device *bind_dev;     /* bound physical interface */
	u32 bind_ifindex;                /* ifindex of bound device */
	struct ovnet_stats __percpu *stats;
	struct nf_hook_ops ingress_hook;
	struct list_head list;
	bool hook_registered;
	char name[IFNAMSIZ];
};

/* Global list of all ovnet devices */
static LIST_HEAD(ovnet_dev_list);
static DEFINE_SPINLOCK(ovnet_lock);

/* ============================================================
 * Statistics — 4.19 compatible (no u64_stats_set/read/inc/add)
 * ============================================================ */
static void ovnet_stats_init(struct ovnet_dev *ovnet)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct ovnet_stats *s = per_cpu_ptr(ovnet->stats, cpu);
		/* In 4.19, just direct-assign during init (no concurrency yet) */
		s->tx_packets = 0;
		s->tx_bytes = 0;
		s->rx_packets = 0;
		s->rx_bytes = 0;
	}
}

static struct rtnl_link_stats64 *ovnet_get_stats64(struct net_device *dev,
						    struct rtnl_link_stats64 *tot)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);
	int cpu;

	for_each_possible_cpu(cpu) {
		const struct ovnet_stats *s = per_cpu_ptr(ovnet->stats, cpu);
		unsigned int start;
		u64 tx_packets, tx_bytes, rx_packets, rx_bytes;

		do {
			start = u64_stats_fetch_begin_irq(&s->syncp);
			/* 4.19: direct read instead of u64_stats_read() */
			tx_packets = s->tx_packets;
			tx_bytes = s->tx_bytes;
			rx_packets = s->rx_packets;
			rx_bytes = s->rx_bytes;
		} while (u64_stats_fetch_retry_irq(&s->syncp, start));

		tot->tx_packets += tx_packets;
		tot->tx_bytes   += tx_bytes;
		tot->rx_packets += rx_packets;
		tot->rx_bytes   += rx_bytes;
	}
	return tot;
}

/* ============================================================
 * Netfilter ingress hook — receive packets from bound device
 * ============================================================ */
static unsigned int ovnet_dev_ingress_hook(void *priv,
					    struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	struct net_device *ovnet_ndev;
	struct ovnet_dev *ovnet;
	struct ovnet_stats *s;

	/* Find the ovnet device bound to this physical interface */
	spin_lock(&ovnet_lock);
	list_for_each_entry(ovnet, &ovnet_dev_list, list) {
		if (ovnet->bind_dev == state->in && ovnet->netdev) {
			ovnet_ndev = ovnet->netdev;
			spin_unlock(&ovnet_lock);

			/* Forward the packet into the ovnet interface */
			skb->dev = ovnet_ndev;
			skb_pull(skb, ETH_HLEN);

			s = this_cpu_ptr(ovnet->stats);
			u64_stats_update_begin(&s->syncp);
			/* 4.19: direct increment instead of u64_stats_inc() */
			s->rx_packets++;
			s->rx_bytes += skb->len;
			u64_stats_update_end(&s->syncp);

			netif_rx(skb);
			return NF_STOLEN;
		}
	}
	spin_unlock(&ovnet_lock);

	return NF_ACCEPT;
}

/* ============================================================
 * Device operations
 * ============================================================ */
static int ovnet_open(struct net_device *dev)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);

	netif_tx_start_all_queues(dev);

	/* Register ingress hook if we have a bound device */
	if (ovnet->bind_dev && !ovnet->hook_registered) {
		ovnet->ingress_hook.hook = ovnet_dev_ingress_hook;
		/* 4.19: use hooknum instead of hook_ops_type */
		ovnet->ingress_hook.hooknum = NF_NETDEV_INGRESS;
		ovnet->ingress_hook.pf = NFPROTO_NETDEV;
		ovnet->ingress_hook.dev = ovnet->bind_dev;

		if (nf_register_net_hook(dev_net(dev), &ovnet->ingress_hook) == 0) {
			ovnet->hook_registered = true;
			pr_info("OVNET:nf_register_net_hook succ (%s)\n", dev->name);
		} else {
			pr_err("OVNET:nf_register_net_hook failed! (%s)\n", dev->name);
		}
	}

	pr_info("OVNET:device open... %s\n", dev->name);
	return 0;
}

static int ovnet_close(struct net_device *dev)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);

	if (ovnet->hook_registered) {
		nf_unregister_net_hook(dev_net(dev), &ovnet->ingress_hook);
		ovnet->hook_registered = false;
		pr_info("OVNET:unregister net hook! %s\n", dev->name);
	}

	netif_tx_stop_all_queues(dev);
	pr_info("OVNET:device close... %s\n", dev->name);
	return 0;
}

static netdev_tx_t ovnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);
	struct ovnet_stats *s;
	struct net_device *tdev;
	int ret;

	s = this_cpu_ptr(ovnet->stats);
	u64_stats_update_begin(&s->syncp);
	/* 4.19: direct increment instead of u64_stats_inc()/u64_stats_add() */
	s->tx_packets++;
	s->tx_bytes += skb->len;
	u64_stats_update_end(&s->syncp);

	/* If no bound device, just drop */
	tdev = ovnet->bind_dev;
	if (!tdev) {
		pr_debug("OVNET:bind_dev is null! dropping on %s\n", dev->name);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* Forward via neigh_xmit on bound device.
	 * 4.19: use NEIGH_ARP_TABLE / NEIGH_ND_TABLE constants directly,
	 * avoiding ipv6_stub dependency (not EXPORT_SYMBOL'd for modules).
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		if (!iph) {
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		ret = neigh_xmit(NEIGH_ARP_TABLE, tdev, &iph->daddr, skb);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph6 = ipv6_hdr(skb);
		if (!iph6) {
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		ret = neigh_xmit(NEIGH_ND_TABLE, tdev, &iph6->daddr, skb);
	} else {
		/* Non-IP: just forward directly */
		skb->dev = tdev;
		dev_queue_xmit(skb);
		return NETDEV_TX_OK;
	}

	if (ret)
		pr_debug("OVNET:ovnet_xmit skb %s return %d\n", dev->name, ret);

	return NETDEV_TX_OK;
}

static int ovnet_validate_addr(struct net_device *dev)
{
	pr_info("OVNET:ovnet_validate_addr %s\n", dev->name);
	return eth_validate_addr(dev);
}

static const struct net_device_ops ovnet_netdev_ops = {
	.ndo_open           = ovnet_open,
	.ndo_stop           = ovnet_close,
	.ndo_start_xmit     = ovnet_xmit,
	.ndo_get_stats64    = ovnet_get_stats64,
	.ndo_validate_addr  = ovnet_validate_addr,
	.ndo_set_mac_address = eth_mac_addr,
};

/* ============================================================
 * RTNL link operations
 * ============================================================ */
static const struct nla_policy ovnet_nl_policy[IFLA_OVNET_MAX + 1] = {
	[IFLA_OVNET_BIND_IFINDEX] = { .type = NLA_U32 },
};

static void ovnet_setup(struct net_device *dev)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);

	ether_setup(dev);
	dev->netdev_ops = &ovnet_netdev_ops;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->features |= NETIF_F_LLTX;
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;

	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = ETH_MAX_MTU;

	memset(ovnet, 0, sizeof(*ovnet));
	ovnet->netdev = dev;
	INIT_LIST_HEAD(&ovnet->list);
}

static int ovnet_validate(struct nlattr *tb[], struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static int ovnet_newlink(struct net *net, struct net_device *dev,
			 struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);
	int err;

	pr_info("OVNET:ovnet_newlink ...%s %p %p %p\n", dev->name, net, tb, data);

	if (data && data[IFLA_OVNET_BIND_IFINDEX]) {
		ovnet->bind_ifindex = nla_get_u32(data[IFLA_OVNET_BIND_IFINDEX]);
		pr_info("OVNET:ovnet_newlink check data %d\n", ovnet->bind_ifindex);
	}

	err = register_netdevice(dev);
	if (err) {
		pr_err("OVNET:register_netdevice failed! %d\n", err);
		return err;
	}
	pr_info("OVNET:register_netdevice succ!\n");

	/* Resolve bind device */
	if (ovnet->bind_ifindex) {
		ovnet->bind_dev = __dev_get_by_index(net, ovnet->bind_ifindex);
		if (ovnet->bind_dev) {
			pr_info("OVNET:register_dev .. %u -> %s\n",
				ovnet->bind_ifindex, ovnet->bind_dev->name);
		} else {
			pr_err("OVNET:get dev failed! ifindex=%u\n",
			       ovnet->bind_ifindex);
		}
	}

	/* Allocate percpu stats */
	ovnet->stats = netdev_alloc_pcpu_stats(struct ovnet_stats);
	if (!ovnet->stats) {
		unregister_netdevice(dev);
		return -ENOMEM;
	}
	ovnet_stats_init(ovnet);

	/* Add to global list */
	spin_lock(&ovnet_lock);
	list_add_tail(&ovnet->list, &ovnet_dev_list);
	spin_unlock(&ovnet_lock);

	return 0;
}

static void ovnet_dellink(struct net_device *dev, struct list_head *head)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);

	pr_info("OVNET:ovnet_dellink ....%s\n", dev->name);

	if (ovnet->hook_registered) {
		nf_unregister_net_hook(dev_net(dev), &ovnet->ingress_hook);
		ovnet->hook_registered = false;
	}

	spin_lock(&ovnet_lock);
	list_del(&ovnet->list);
	spin_unlock(&ovnet_lock);

	if (ovnet->stats)
		free_percpu(ovnet->stats);

	unregister_netdevice_queue(dev, head);
}

static int ovnet_changelink(struct net_device *dev, struct nlattr *tb[],
			    struct nlattr *data[],
			    struct netlink_ext_ack *extack)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);
	u32 new_ifindex;

	pr_info("OVNET:ovnet_changelink ....%s %p %p %p\n",
		dev->name, dev, tb, data);

	if (!data || !data[IFLA_OVNET_BIND_IFINDEX])
		return 0;

	new_ifindex = nla_get_u32(data[IFLA_OVNET_BIND_IFINDEX]);

	if (ovnet->bind_ifindex != new_ifindex) {
		pr_info("OVNET:change bind if %u -> %u\n",
			ovnet->bind_ifindex, new_ifindex);

		/* Unregister old hook */
		if (ovnet->hook_registered) {
			nf_unregister_net_hook(dev_net(dev), &ovnet->ingress_hook);
			ovnet->hook_registered = false;
		}

		ovnet->bind_ifindex = new_ifindex;
		ovnet->bind_dev = __dev_get_by_index(dev_net(dev), new_ifindex);

		if (ovnet->bind_dev && netif_running(dev)) {
			ovnet->ingress_hook.hook = ovnet_dev_ingress_hook;
			ovnet->ingress_hook.pf = NFPROTO_NETDEV;
			/* 4.19: use hooknum instead of hook_ops_type */
			ovnet->ingress_hook.hooknum = NF_NETDEV_INGRESS;
			ovnet->ingress_hook.dev = ovnet->bind_dev;
			if (nf_register_net_hook(dev_net(dev), &ovnet->ingress_hook) == 0)
				ovnet->hook_registered = true;
		}
	}

	return 0;
}

static size_t ovnet_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(u32)); /* IFLA_OVNET_BIND_IFINDEX */
}

static int ovnet_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct ovnet_dev *ovnet = netdev_priv(dev);

	if (ovnet->bind_ifindex &&
	    nla_put_u32(skb, IFLA_OVNET_BIND_IFINDEX, ovnet->bind_ifindex))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops ovnet_link_ops __read_mostly = {
	.kind         = "ovnet",
	.maxtype      = IFLA_OVNET_MAX,
	.policy       = ovnet_nl_policy,
	.priv_size    = sizeof(struct ovnet_dev),
	.setup        = ovnet_setup,
	.validate     = ovnet_validate,
	.newlink      = ovnet_newlink,
	.dellink      = ovnet_dellink,
	.changelink   = ovnet_changelink,
	.get_size     = ovnet_get_size,
	.fill_info    = ovnet_fill_info,
};

/* ============================================================
 * Sysctl — /proc/sys/net/ovnet_dev
 * ============================================================ */
static int ovnet_bind_ifindex = 0;

static struct ctl_table ovnet_sysctl_template[] = {
	{
		.procname = "bind_ifindex",
		.data     = &ovnet_bind_ifindex,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = proc_dointvec,
	},
	{ }
};

static struct ctl_table_header *s_ovnet_dev_sysctl_table;

static void ovnet_register_sysctl(void)
{
	s_ovnet_dev_sysctl_table = register_net_sysctl(&init_net,
							"net/ovnet_dev",
							ovnet_sysctl_template);
}

static void ovnet_unregister_sysctl(void)
{
	if (s_ovnet_dev_sysctl_table)
		unregister_net_sysctl_table(s_ovnet_dev_sysctl_table);
}

/* ============================================================
 * Module init/exit — create default ovnet devices
 * ============================================================ */
static struct net_device *ovnet_default_devs[OVNET_MAX_DEVS];

static int __init ovnet_init_module(void)
{
	int i, err;

	pr_info("OVNET:ovnet_dev_init...\n");

	err = rtnl_link_register(&ovnet_link_ops);
	if (err) {
		pr_err("OVNET:rtnl_link_register failed! %d\n", err);
		return err;
	}

	/* Create default ovnet devices */
	if (numvnets > OVNET_MAX_DEVS)
		numvnets = OVNET_MAX_DEVS;

	for (i = 0; i < numvnets; i++) {
		char name[IFNAMSIZ];
		struct net_device *dev;
		struct ovnet_dev *ovnet;

		snprintf(name, IFNAMSIZ, "ovnet%d", i);

		dev = alloc_netdev(sizeof(struct ovnet_dev), name,
				   NET_NAME_UNKNOWN, ovnet_setup);
		if (!dev) {
			pr_err("OVNET:alloc_netdev failed for %s\n", name);
			err = -ENOMEM;
			goto err_out;
		}

		eth_hw_addr_random(dev);

		err = register_netdevice(dev);
		if (err) {
			pr_err("OVNET:register_netdevice failed! %d\n", err);
			free_netdev(dev);
			goto err_out;
		}

		ovnet = netdev_priv(dev);
		ovnet->stats = netdev_alloc_pcpu_stats(struct ovnet_stats);
		if (!ovnet->stats) {
			unregister_netdevice(dev);
			free_netdev(dev);
			err = -ENOMEM;
			goto err_out;
		}
		ovnet_stats_init(ovnet);

		spin_lock(&ovnet_lock);
		list_add_tail(&ovnet->list, &ovnet_dev_list);
		spin_unlock(&ovnet_lock);

		ovnet_default_devs[i] = dev;
		pr_info("OVNET:register_dev .. %u %s\n", dev->ifindex, dev->name);
	}

	ovnet_register_sysctl();
	pr_info("OVNET:oplus_network_vnet loaded, %d devices created\n", numvnets);
	return 0;

err_out:
	pr_err("OVNET:init default ovnet device failed! %d\n", err);
	for (i = 0; i < numvnets && ovnet_default_devs[i]; i++) {
		unregister_netdevice(ovnet_default_devs[i]);
		free_netdev(ovnet_default_devs[i]);
		ovnet_default_devs[i] = NULL;
	}
	rtnl_link_unregister(&ovnet_link_ops);
	return err;
}

static void __exit ovnet_cleanup_module(void)
{
	int i;

	ovnet_unregister_sysctl();

	for (i = 0; i < numvnets && ovnet_default_devs[i]; i++) {
		struct ovnet_dev *ovnet = netdev_priv(ovnet_default_devs[i]);

		if (ovnet->hook_registered) {
			nf_unregister_net_hook(dev_net(ovnet_default_devs[i]),
					       &ovnet->ingress_hook);
		}
		if (ovnet->stats)
			free_percpu(ovnet->stats);

		unregister_netdev(ovnet_default_devs[i]);
		pr_info("OVNET:ovnet_unregister_dev .... %s\n",
			ovnet_default_devs[i]->name);
		ovnet_default_devs[i] = NULL;
	}

	rtnl_link_unregister(&ovnet_link_ops);
	pr_info("OVNET:oplus_network_vnet unloaded\n");
}

module_init(ovnet_init_module);
module_exit(ovnet_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ColorOS Port Project");
MODULE_DESCRIPTION("OPPO Virtual Network Interface (ovnet) for cross-device interconnection");
MODULE_VERSION("1.0-4.19");
MODULE_ALIAS_RTNL_LINK("ovnet");
