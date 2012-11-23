#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#include <linux/if_arp.h>

#define DEVICE_MTU	(TIPC_MAX_USER_MSG_SIZE - 100)
#define DEVICE_TXQ	255

static void tipc_dev_setup(struct net_device *dev);
static int tipc_dev_init(struct net_device *dev);
static void tipc_dev_free(struct net_device *dev);
static netdev_tx_t tipc_xmit(struct sk_buff *skb, struct net_device *dev);
static struct rtnl_link_stats64 *tipc_get_stats64(struct net_device *dev,
						  struct rtnl_link_stats64 *stats);

static struct rtnl_link_ops tipc_link_ops __read_mostly = {
	.kind		= "tipc",
	.setup		= tipc_dev_setup,
};

static const struct net_device_ops tipc_netdev_ops = {
	.ndo_init		= tipc_dev_init,
	.ndo_start_xmit		= tipc_xmit,
	.ndo_get_stats64	= tipc_get_stats64,
};


struct net_device *dev_tipc;



/**
 * tipc_dev_start - start the tunnel device
 */
int tipc_dev_start(struct work_struct *work)
{
	int err = 0;

	kfree(work);
	if (dev_tipc) {
		pr_err("%s already enabled\n", dev_tipc->name);
		return -1;
	}

	rtnl_lock();
	err = __rtnl_link_register(&tipc_link_ops);
	dev_tipc = alloc_netdev(0, "tipc%d", tipc_dev_setup);
	if (!dev_tipc)
		return -ENOMEM;
	dev_tipc->rtnl_link_ops = &tipc_link_ops;
	err = register_netdevice(dev_tipc);
	if (err < 0) {
		free_netdev(dev_tipc);
		__rtnl_link_unregister(&tipc_link_ops);
	}
	rtnl_unlock();

	return err;
}

/**
 * tipc_dev_stop - stop the tunnel device
 */
void tipc_dev_stop(struct work_struct *work)
{
	kfree(work);
	if (!dev_tipc) {
		pr_err("device not enabled\n");
		return;
	}
	rtnl_lock();
	unregister_netdevice(dev_tipc);
	__rtnl_link_unregister(&tipc_link_ops);
	rtnl_unlock();
}


/**
 * tipc_dev_init - netdev initialization callback
 */
static int tipc_dev_init(struct net_device *dev)
{
	return 0;
}

/**
 * tipc_dev_setup - basic netdevice setup
 */
static void tipc_dev_setup(struct net_device *dev)
{
	/* Initialize the device structure. */
	dev->netdev_ops = &tipc_netdev_ops;
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->mtu = DEVICE_MTU;
	dev->addr_len = 0;
	dev->tx_queue_len = DEVICE_TXQ;
	dev->flags |= IFF_NOARP;
	dev->flags |= IFF_BROADCAST;
	dev->priv_flags |= IFF_TX_SKB_SHARING | IFF_DONT_BRIDGE;
	dev->features |= NETIF_F_VLAN_CHALLENGED;
	dev->destructor = tipc_dev_free;
}

/**
 * tipc_dev_free - netdev teardown callback
 */
static void tipc_dev_free(struct net_device *dev)
{
	free_netdev(dev);
}

/**
 * tipc_xmit - enqueue packets for tipc to deliver
 *
 */
static netdev_tx_t tipc_xmit(struct sk_buff *skb, struct net_device *dev)
{
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
}

static struct rtnl_link_stats64 *tipc_get_stats64(struct net_device *dev,
					struct rtnl_link_stats64 *stats)
{
	return stats;
}

