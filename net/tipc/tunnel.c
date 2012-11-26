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
#define HASH_ON_SOURCE	1
#define PORTID_HLIST_SIZE	512



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

/**
 * struct tipc_dest - ip to tipc portid mapping entry
 * @ip:	IP address
 * @portid: TIPC port ID
 * @chain: Collision chain list
 * @next: Next entry
 */
struct tipc_dest
{
	struct sockaddr_storage ip;
	struct sockaddr_tipc portid;
	struct list_head chain;
};

/**
 * struct pcpu_dstats - interface statistics
 */
struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	u64			tx_errors;
	u64			tx_dropped;
	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_errors;
	struct u64_stats_sync	syncp;
};

struct net_device *dev_tipc;
struct socket *tunnel_sock;
static struct sk_buff_head tx_queue;
struct task_struct *ts_recv;
struct task_struct *ts_xmit;
static struct tipc_dest *portid_hlist[PORTID_HLIST_SIZE];


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
 * hash_gen_ip - calculate hash over source or dest ip
 * @skb:	buffer holding the IP packet
 * @ss:		output buffer holding the IP address
 * @field:	select source or dest IP
 */
static int hash_gen_ip(struct sk_buff *skb, struct sockaddr_storage *ss,
		       int field)
{
	struct sockaddr_in *v4;
	struct sockaddr_in6 *v6;

	memset(ss, 0, sizeof(struct sockaddr_storage));
	switch (ip_hdr(skb)->version)
	{
		case 4:
			v4 = (struct sockaddr_in*) ss;
			v4->sin_family = AF_INET;
			field == HASH_ON_SOURCE ?
				(v4->sin_addr.s_addr = ip_hdr(skb)->saddr) :
				(v4->sin_addr.s_addr = ip_hdr(skb)->daddr);
			return jhash(&v4->sin_addr.s_addr,
				     sizeof(struct in_addr), 0) &
				     (PORTID_HLIST_SIZE - 1);
			break;
		case 6:
			v6 = (struct sockaddr_in6*) ss;
			v6->sin6_family = AF_INET6;
			field == HASH_ON_SOURCE ?
				memcpy(&v6->sin6_addr, &ipv6_hdr(skb)->saddr,
				       sizeof(struct in6_addr)) :
				memcpy(&v6->sin6_addr, &ipv6_hdr(skb)->daddr,
				       sizeof(struct in6_addr));
			return jhash(&v6->sin6_addr,
				     sizeof(struct in6_addr), 0) &
				     (PORTID_HLIST_SIZE - 1);
			break;
		default:
			pr_err("Not an IP packet\n");
		return -1;
		break;
	}
	return -1;
}

/**
 * get_dest - find an a destination entry based on ip
 * @hash: remote ip hashv
 * @ip:   remote ip
 */
static struct tipc_dest* get_dest(int hash, struct sockaddr_storage *ip)
{
	struct tipc_dest *entry_p;
	struct list_head *chain;

	entry_p = portid_hlist[hash];
	if (!entry_p)
		return NULL;
	list_for_each(chain, &entry_p->chain) {
		entry_p = list_entry(chain, struct tipc_dest, chain);
		if (!memcmp(&entry_p->ip, ip, sizeof(struct sockaddr_storage)))
			break;
	}
	return entry_p;
}

/**
 * allocate_dest - allocate a new dest entry and add it to the list
 * @hash: remote ip hashv
 * @ip:   remote ip
 * @id:   remote tipc portid
 */
static void allocate_dest(int hash, struct sockaddr_storage *ip,
			struct sockaddr_tipc *portid)
{
	struct tipc_dest *new_p;

	new_p = kzalloc(sizeof(struct tipc_dest), GFP_KERNEL);
	if (!new_p) {
		pr_err("out of memory!\n");
		return;
	}
	memcpy(&new_p->ip, ip, sizeof(struct sockaddr_storage));
	memcpy(&new_p->portid, portid, sizeof(struct sockaddr_tipc));
	if (!portid_hlist[hash]) {
		portid_hlist[hash] = new_p;
		INIT_LIST_HEAD(&new_p->chain);
		return;
	}
	list_add(&new_p->chain, &portid_hlist[hash]->chain);
}

/**
 * tipc_recv_wh - receive packets from the tipc socket and deliver to interface
 *
 */
static int tipc_recv_wh(void *data)
{
	struct sk_buff *skb;
	struct sockaddr_tipc r_addr;
	struct sockaddr_storage ss;
	struct tipc_dest *dest;
	struct pcpu_dstats *dstats;
	int res;

	res = kernel_bind(tunnel_sock, (struct sockaddr*) &tipc_listen_addr,
			  sizeof(struct sockaddr_tipc));
	if (res < 0) {
		pr_err("unable to bind kernel socket: %u\n", res);
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
		r_addr.family = AF_TIPC;
		r_addr.addrtype = TIPC_ADDR_ID;
		r_addr.addr.id.ref = msg_origport(buf_msg(skb));
		r_addr.addr.id.node = msg_orignode(buf_msg(skb));
		r_addr.addr.name.domain = 0;
		r_addr.scope = 0;

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
		dstats = this_cpu_ptr(dev_tipc->dstats);
		u64_stats_update_begin(&dstats->syncp);
		if ((res = hash_gen_ip(skb, &ss, HASH_ON_SOURCE)) == -1)
			goto rx_invalid;
		dest = get_dest(res, &ss);
		if (!dest)
			allocate_dest(res, &ss, &r_addr);
		if (set_skb_proto(skb)) {
			dstats->rx_packets++;
			dstats->rx_bytes += skb->len;
			u64_stats_update_end(&dstats->syncp);
			netif_rx(skb);
		}else { 
rx_invalid:
			dstats->rx_errors++;
			u64_stats_update_end(&dstats->syncp);
			kfree_skb(skb);
		}
	}
}

/**
 * tipc_xmit_wh - deliver packets to the tipc socket
 *
 */
static int tipc_xmit_wh(void *data)
{
	struct sk_buff *skb;
	struct sockaddr_storage ss;
	struct tipc_dest *dest;
	struct tipc_port *tport;
	struct pcpu_dstats *dstats;
	struct kvec iov;
	int res;

xmit:
	wait_event_interruptible(*sk_sleep(tunnel_sock->sk),
				 !skb_queue_empty(&tx_queue) ||
				 kthread_should_stop());
	while (!skb_queue_empty(&tx_queue)) {
		skb = skb_dequeue_tail(&tx_queue);
		if ((res = hash_gen_ip(skb, &ss, !HASH_ON_SOURCE)) == -1) {
			dstats = this_cpu_ptr(dev_tipc->dstats);
			u64_stats_update_begin(&dstats->syncp);
			dstats->tx_errors++;
			u64_stats_update_end(&dstats->syncp);
			kfree_skb(skb);
			goto xmit;
		}
		dest = get_dest(res, &ss);
		tport = tipc_sk_port(tunnel_sock->sk);
		iov.iov_base = skb->data;
		iov.iov_len = skb->len;
again:
		lock_sock(tunnel_sock->sk);
		if (dest) {
			res = tipc_send2port(tport->ref,
					     &dest->portid.addr.id,
					     1,
					     (const struct iovec*)&iov,
					     skb->len);

		} else {
			res = tipc_multicast(tport->ref,
					     &tipc_listen_addr.addr.nameseq,
					     1,
					     (const struct iovec*)&iov,
					     skb->len);
		}
		if (unlikely(res == -ELINKCONG)) {
			release_sock(tunnel_sock->sk);
			wait_event_interruptible(*sk_sleep(tunnel_sock->sk),
						 !tport->congested);
			goto again;
		}
		release_sock(tunnel_sock->sk);
		dstats = this_cpu_ptr(dev_tipc->dstats);
		u64_stats_update_begin(&dstats->syncp);
		dstats->tx_packets++;
		dstats->tx_bytes += skb->len;
		u64_stats_update_end(&dstats->syncp);
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
	memset(portid_hlist, 0, (sizeof(struct tipc_dest*) * PORTID_HLIST_SIZE));

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
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
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
	free_percpu(dev->dstats);
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
	int i;
	const struct pcpu_dstats *dstats;
	u64 tbytes;
	u64 tpackets;
	u64 terrors;
	u64 tdropped;
	u64 rbytes;
	u64 rpackets;
	u64 rerrors;
	unsigned int start;

	for_each_possible_cpu(i) {
		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
			terrors = dstats->tx_errors;
			tdropped = dstats->tx_dropped;
			rbytes = dstats->rx_bytes;
			rpackets = dstats->rx_packets;
			rerrors = dstats->rx_errors;
		} while (u64_stats_fetch_retry(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
		stats->tx_errors += terrors;
		stats->tx_dropped += tdropped;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpackets;
		stats->rx_errors += rerrors;
	}
	return stats;

}

