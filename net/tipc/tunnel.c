#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/kthread.h>
#include <net/xfrm.h>
#include <net/ip.h>

#include "core.h"
#include "port.h"

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

/**
 * tipc_listen_addr - multicast listener address
 */
static struct sockaddr_tipc tipc_listen_addr = {
	.family = AF_TIPC,
	.addrtype = TIPC_ADDR_NAMESEQ,
	.addr.nameseq.type = TIPC_DEV_SRV,
	.addr.nameseq.lower = 0,
	.addr.nameseq.upper = 0,
	.scope = TIPC_ZONE_SCOPE
};


struct net_device *dev_tipc;
struct socket *tunnel_sock;
static struct sk_buff_head tx_queue;
struct task_struct *ts_recv;
struct task_struct *ts_xmit;

static int set_skb_proto(struct sk_buff *skb)
{
	switch (ip_hdr(skb)->version) {
		case 4:
			skb->protocol = htons(ETH_P_IP);
			break;
		case 6:
			skb->protocol = htons(ETH_P_IPV6);
			break;
		default:
			return -1;
	}
	return 1;
}

/**
 * tipc_recv_wh - receive packets from the tipc socket and deliver to interface
 *
 */
static int tipc_recv_wh(void *data)
{
	struct sk_buff *skb;
	int ret;

	ret = kernel_bind(tunnel_sock, (struct sockaddr*) &tipc_listen_addr,
			  sizeof(struct sockaddr_tipc));
	if (ret < 0) {
		pr_err("unable to bind kernel socket: %u\n", ret);
		return 0;
	}

	while (1)
	{
		wait_event_interruptible(*sk_sleep(tunnel_sock->sk),
			!skb_queue_empty(&tunnel_sock->sk->sk_receive_queue) ||
			kthread_should_stop());
		if (kthread_should_stop())
			return 0;
		lock_sock(tunnel_sock->sk);
		skb = __skb_dequeue(&tunnel_sock->sk->sk_receive_queue);
		//FIXME: global recv counter in socket.c breaks this.......
		release_sock(tunnel_sock->sk);

		/* We will receive a copy of messages multicasted to
		 * the tipc_listen_addr, but we dont want the ones we
		 * sent ourselves to be delivered to the netif, so drop them
		 */
		//FIXME: multicast-loop sockopt for tipc
		if (msg_orignode(buf_msg(skb)) == tipc_own_addr) {
			kfree_skb(skb);
			continue;
		}
		skb_orphan(skb);
		nf_reset(skb);
		skb->skb_iif = 0;
		skb->dev = dev_tipc;
		skb_dst_drop(skb);
		skb->pkt_type = PACKET_HOST;
		secpath_reset(skb);
		nf_reset(skb);
		skb_pull(skb, msg_hdr_sz(buf_msg(skb)));
		skb->mac_len = 0;			//TODO:remove?
		skb_set_network_header(skb,0);
		if (set_skb_proto(skb))
			netif_rx(skb);
		else
			kfree_skb(skb);
	}
}

/**
 * tipc_xmit_wh - deliver packets to the tipc socket
 *
 */
static int tipc_xmit_wh(void *data)
{
	struct sk_buff *skb;
	struct tipc_port *tport;
	struct kvec iov;
	int res;

xmit:
	wait_event_interruptible(*sk_sleep(tunnel_sock->sk),
				 !skb_queue_empty(&tx_queue) ||
				 kthread_should_stop());
	while (!skb_queue_empty(&tx_queue)) {
		skb = skb_dequeue_tail(&tx_queue);
		tport = tipc_sk_port(tunnel_sock->sk);
		iov.iov_base = skb->data;
		iov.iov_len = skb->len;
again:
		lock_sock(tunnel_sock->sk);
		res = tipc_multicast(tport->ref,
				     &tipc_listen_addr.addr.nameseq,
				     1,
				     (const struct iovec*)&iov,
				     skb->len);
		if (unlikely(res == -ELINKCONG)) {
			release_sock(tunnel_sock->sk);
			wait_event_interruptible(*sk_sleep(tunnel_sock->sk),
						 !tport->congested);
			goto again;
		}
		release_sock(tunnel_sock->sk);
		kfree_skb(skb);
		if (skb_queue_len(&tx_queue) <= (DEVICE_TXQ / 2))
			netif_wake_queue(dev_tipc);
	}
	if(kthread_should_stop())
		return 0;
	goto xmit;
}

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
	err = sock_create_kern(AF_TIPC, SOCK_RDM, 0, &tunnel_sock);
	if (err)
		pr_err("error in sock create\n");

	skb_queue_head_init(&tx_queue);
	ts_recv = kthread_run(tipc_recv_wh, NULL, "tipc_recv_wh");
	ts_xmit = kthread_run(tipc_xmit_wh, NULL, "tipc_xmit_wh");
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
	struct sk_buff *skb;
	kfree(work);
	if (!dev_tipc) {
		pr_err("device not enabled\n");
		return;
	}
	rtnl_lock();
	unregister_netdevice(dev_tipc);
	__rtnl_link_unregister(&tipc_link_ops);
	rtnl_unlock();
	sock_release(tunnel_sock);
        while ((skb = skb_dequeue_tail(&tx_queue)))
		kfree_skb(skb);
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
	spin_lock_bh(&tx_queue.lock);
	if (skb_queue_len(&tx_queue) >= DEVICE_TXQ) {
		spin_unlock_bh(&tx_queue.lock);
		netif_stop_queue(dev);
		return NETDEV_TX_BUSY;
	}
	__skb_queue_head(&tx_queue, skb);
	spin_unlock_bh(&tx_queue.lock);
	wake_up_interruptible(sk_sleep(tunnel_sock->sk));
	return NETDEV_TX_OK;
}

static struct rtnl_link_stats64 *tipc_get_stats64(struct net_device *dev,
					struct rtnl_link_stats64 *stats)
{
	return stats;
}

