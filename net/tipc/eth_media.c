/*
 * net/tipc/eth_media.c: Ethernet bearer support for TIPC
 *
 * Copyright (c) 2001-2007, Ericsson AB
 * Copyright (c) 2005-2008, 2011, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core.h"
#include "bearer.h"
#include "msg.h"
#include <net/protocol.h>

#define MAX_ETH_BEARERS		MAX_BEARERS

#define ETH_ADDR_OFFSET	4	/* message header offset of MAC address */

/**
 * struct eth_bearer - Ethernet bearer data structure
 * @bearer: ptr to associated "generic" bearer structure
 * @dev: ptr to associated Ethernet network device
 * @tipc_packet_type: used in binding TIPC to Ethernet driver
 * @setup: work item used when enabling bearer
 * @cleanup: work item used when disabling bearer
 */
struct eth_bearer {
	struct tipc_bearer *bearer;
	struct net_device *dev;
	struct packet_type tipc_packet_type;
	struct work_struct setup;
	struct work_struct cleanup;
};

static struct tipc_media eth_media_info;
static struct eth_bearer eth_bearers[MAX_ETH_BEARERS];
static int eth_started;

static int recv_notification(struct notifier_block *nb, unsigned long evt,
			      void *dv);
/*
 * Network device notifier info
 */
static struct notifier_block notifier = {
	.notifier_call	= recv_notification,
	.priority	= 0
};

/**
 * eth_media_addr_set - initialize Ethernet media address structure
 *
 * Media-dependent "value" field stores MAC address in first 6 bytes
 * and zeroes out the remaining bytes.
 */
static void eth_media_addr_set(struct tipc_media_addr *a, char *mac)
{
	memcpy(a->value, mac, ETH_ALEN);
	memset(a->value + ETH_ALEN, 0, sizeof(a->value) - ETH_ALEN);
	a->media_id = TIPC_MEDIA_TYPE_ETH;
	a->broadcast = !memcmp(mac, eth_media_info.bcast_addr.value, ETH_ALEN);
}

/**
 * send_msg - send a TIPC message out over an Ethernet interface
 */
static int send_msg(struct sk_buff *buf, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	struct sk_buff *clone;
	struct net_device *dev;
	int delta;

	clone = skb_clone(buf, GFP_ATOMIC);
	if (!clone)
		return 0;

	dev = ((struct eth_bearer *)(tb_ptr->usr_handle))->dev;
	delta = dev->hard_header_len - skb_headroom(buf);

	if ((delta > 0) &&
	    pskb_expand_head(clone, SKB_DATA_ALIGN(delta), 0, GFP_ATOMIC)) {
		kfree_skb(clone);
		return 0;
	}

	skb_reset_network_header(clone);
	clone->dev = dev;
	dev_hard_header(clone, dev, ETH_P_TIPC, dest->value,
			dev->dev_addr, clone->len);
	dev_queue_xmit(clone);
	return 0;
}

/**
 * recv_msg - handle incoming TIPC message from an Ethernet interface
 *
 * Accept only packets explicitly sent to this node, or broadcast packets;
 * ignores packets sent using Ethernet multicast, and traffic sent to other
 * nodes (which can happen if interface is running in promiscuous mode).
 */
static int recv_msg(struct sk_buff *buf, struct net_device *dev,
		    struct packet_type *pt, struct net_device *orig_dev)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)pt->af_packet_priv;

	if (!net_eq(dev_net(dev), &init_net)) {
		kfree_skb(buf);
		return 0;
	}

	if (likely(eb_ptr->bearer)) {
		if (likely(buf->pkt_type <= PACKET_BROADCAST)) {
			buf->next = NULL;
			tipc_recv_msg(buf, eb_ptr->bearer);
			return 0;
		}
	}
	kfree_skb(buf);
	return 0;
}

/**
 * setup_bearer - setup association between Ethernet bearer and interface
 */
static void setup_bearer(struct work_struct *work)
{
	struct eth_bearer *eb_ptr =
		container_of(work, struct eth_bearer, setup);

	dev_add_pack(&eb_ptr->tipc_packet_type);
}

/**
 * enable_bearer - attach TIPC bearer to an Ethernet interface
 */
static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct net_device *dev = NULL;
	struct net_device *pdev = NULL;
	struct eth_bearer *eb_ptr = &eth_bearers[0];
	struct eth_bearer *stop = &eth_bearers[MAX_ETH_BEARERS];
	char *driver_name = strchr((const char *)tb_ptr->name, ':') + 1;
	int pending_dev = 0;

	/* Find unused Ethernet bearer structure */
	while (eb_ptr->dev) {
		if (!eb_ptr->bearer)
			pending_dev++;
		if (++eb_ptr == stop)
			return pending_dev ? -EAGAIN : -EDQUOT;
	}

	/* Find device with specified name */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, pdev) {
		if (!strncmp(pdev->name, driver_name, IFNAMSIZ)) {
			dev = pdev;
			dev_hold(dev);
			break;
		}
	}
	read_unlock(&dev_base_lock);
	if (!dev)
		return -ENODEV;

	/* Create Ethernet bearer for device */
	eb_ptr->dev = dev;
	eb_ptr->tipc_packet_type.type = htons(ETH_P_TIPC);
	eb_ptr->tipc_packet_type.dev = dev;
	eb_ptr->tipc_packet_type.func = recv_msg;
	eb_ptr->tipc_packet_type.af_packet_priv = eb_ptr;
	INIT_LIST_HEAD(&(eb_ptr->tipc_packet_type.list));
	INIT_WORK(&eb_ptr->setup, setup_bearer);
	schedule_work(&eb_ptr->setup);

	/* Associate TIPC bearer with Ethernet bearer */
	eb_ptr->bearer = tb_ptr;
	tb_ptr->usr_handle = (void *)eb_ptr;
	tb_ptr->mtu = dev->mtu;
	/* The default link window can be overriden by the media value
	 * but can never exceed 3/4 of the interface tx queue length.
	 */
	if (eth_media_info.window)
		tb_ptr->window = min((u32) (dev->tx_queue_len*3/4),
				     (u32) eth_media_info.window);
	else
		tb_ptr->window = clamp((u32) (dev->tx_queue_len*3/4),
				       (u32) TIPC_MIN_LINK_WIN,
				       (u32) TIPC_MAX_LINK_WIN);
	if (!dev->ethtool_ops->get_ringparam) {
		pr_info("Could not get ring parameters from %s\n",
			driver_name);
		tb_ptr->arwindow = TIPC_DEF_LINK_WIN;
	} else {
		struct ethtool_ringparam rp = {
			.cmd = ETHTOOL_GRINGPARAM
			};
		dev->ethtool_ops->get_ringparam(dev, &rp);
		tb_ptr->arwindow = clamp((u32) (rp.rx_pending*3/4),
					 (u32) TIPC_MIN_LINK_WIN,
					 (u32) TIPC_MAX_LINK_WIN);
	}
	tb_ptr->blocked = 0;
	eth_media_addr_set(&tb_ptr->addr, (char *)dev->dev_addr);
	return 0;
}

/**
 * cleanup_bearer - break association between Ethernet bearer and interface
 *
 * This routine must be invoked from a work queue because it can sleep.
 */
static void cleanup_bearer(struct work_struct *work)
{
	struct eth_bearer *eb_ptr =
		container_of(work, struct eth_bearer, cleanup);

	dev_remove_pack(&eb_ptr->tipc_packet_type);
	dev_put(eb_ptr->dev);
	eb_ptr->dev = NULL;
}

/**
 * disable_bearer - detach TIPC bearer from an Ethernet interface
 *
 * Mark Ethernet bearer as inactive so that incoming buffers are thrown away,
 * then get worker thread to complete bearer cleanup.  (Can't do cleanup
 * here because cleanup code needs to sleep and caller holds spinlocks.)
 */
static void disable_bearer(struct tipc_bearer *tb_ptr)
{
	struct eth_bearer *eb_ptr = (struct eth_bearer *)tb_ptr->usr_handle;

	eb_ptr->bearer = NULL;
	INIT_WORK(&eb_ptr->cleanup, cleanup_bearer);
	schedule_work(&eb_ptr->cleanup);
}

/**
 * recv_notification - handle device updates from OS
 *
 * Change the state of the Ethernet bearer (if any) associated with the
 * specified device.
 */
static int recv_notification(struct notifier_block *nb, unsigned long evt,
			     void *dv)
{
	struct net_device *dev = (struct net_device *)dv;
	struct eth_bearer *eb_ptr = &eth_bearers[0];
	struct eth_bearer *stop = &eth_bearers[MAX_ETH_BEARERS];

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	while ((eb_ptr->dev != dev)) {
		if (++eb_ptr == stop)
			return NOTIFY_DONE;	/* couldn't find device */
	}
	if (!eb_ptr->bearer)
		return NOTIFY_DONE;		/* bearer had been disabled */

	eb_ptr->bearer->mtu = dev->mtu;

	switch (evt) {
	case NETDEV_CHANGE:
		if (netif_carrier_ok(dev))
			tipc_continue(eb_ptr->bearer);
		else
			tipc_block_bearer(eb_ptr->bearer->name);
		break;
	case NETDEV_UP:
		tipc_continue(eb_ptr->bearer);
		break;
	case NETDEV_DOWN:
		tipc_block_bearer(eb_ptr->bearer->name);
		break;
	case NETDEV_CHANGEMTU:
	case NETDEV_CHANGEADDR:
		tipc_block_bearer(eb_ptr->bearer->name);
		tipc_continue(eb_ptr->bearer);
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGENAME:
		tipc_disable_bearer(eb_ptr->bearer->name);
		break;
	}
	return NOTIFY_OK;
}

/**
 * eth_addr2str - convert Ethernet address to string
 */
static int eth_addr2str(struct tipc_media_addr *a, char *str_buf, int str_size)
{
	if (str_size < 18)	/* 18 = strlen("aa:bb:cc:dd:ee:ff\0") */
		return 1;

	sprintf(str_buf, "%pM", a->value);
	return 0;
}

/**
 * eth_str2addr - convert string to Ethernet address
 */
static int eth_str2addr(struct tipc_media_addr *a, char *str_buf)
{
	char mac[ETH_ALEN];
	int r;

	r = sscanf(str_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		       (u32 *)&mac[0], (u32 *)&mac[1], (u32 *)&mac[2],
		       (u32 *)&mac[3], (u32 *)&mac[4], (u32 *)&mac[5]);

	if (r != ETH_ALEN)
		return 1;

	eth_media_addr_set(a, mac);
	return 0;
}

/**
 * eth_str2addr - convert Ethernet address format to message header format
 */
static int eth_addr2msg(struct tipc_media_addr *a, char *msg_area)
{
	memset(msg_area, 0, TIPC_MEDIA_ADDR_SIZE);
	msg_area[TIPC_MEDIA_TYPE_OFFSET] = TIPC_MEDIA_TYPE_ETH;
	memcpy(msg_area + ETH_ADDR_OFFSET, a->value, ETH_ALEN);
	return 0;
}

/**
 * eth_str2addr - convert message header address format to Ethernet format
 */
static int eth_msg2addr(struct tipc_media_addr *a, char *msg_area)
{
	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_ETH)
		return 1;

	eth_media_addr_set(a, msg_area + ETH_ADDR_OFFSET);
	return 0;
}

/*
 * Ethernet media registration info
 */
static struct tipc_media eth_media_info = {
	.send_msg	= send_msg,
	.enable_bearer	= enable_bearer,
	.disable_bearer	= disable_bearer,
	.addr2str	= eth_addr2str,
	.str2addr	= eth_str2addr,
	.addr2msg	= eth_addr2msg,
	.msg2addr	= eth_msg2addr,
	.bcast_addr	= { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
			    TIPC_MEDIA_TYPE_ETH, 1 },
	.priority	= TIPC_DEF_LINK_PRI,
	.tolerance	= TIPC_DEF_LINK_TOL,
	.window		= 0,
	.type_id	= TIPC_MEDIA_TYPE_ETH,
	.name		= "eth"
};


static struct sk_buff **rdm_gro_receive(struct sk_buff **head,
				       struct sk_buff *skb)
{
	unsigned int off;
	unsigned int hlen;
	struct tipc_msg *msg;

	msg = buf_msg(skb);

	off = skb_gro_offset(skb);
	hlen = off + msg_hdr_sz(msg);
	return NULL;
}
static int rdm_gro_complete(struct sk_buff *skb)
{
	return 0;
}

//TODO: bake these into an array of some sort
struct net_offload rdm_offload = {
	.callbacks = {
		.gro_receive = rdm_gro_receive,
		.gro_complete = rdm_gro_complete,
	},
};
/*
struct net_offload frag_offload = {
	.callbacks = {
		.gro_receive = frag_gro_receive,
		.gro_complete = frag_gro_complete,
	},
};
*/

static struct sk_buff **conn_gro_receive(struct sk_buff **head,
				       struct sk_buff *skb)
{
	unsigned int off;
	unsigned int hlen;
	unsigned int len;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct tipc_msg *msg;
	struct tipc_msg *th;
	struct tipc_msg *th2;
	unsigned int thlen;
	int flush = 1;

	pr_info("conn_gro_receive\n");

	msg = buf_msg(skb);
	thlen = msg_hdr_sz(msg);
	/*
	pr_info("skb oport=%u \n", msg_origport(msg));
	pr_info("skb dport=%u \n", msg_destport(msg));
	pr_info("skb pnode=0x%x \n", msg_prevnode(msg));
	*/
	off = skb_gro_offset(skb);
	hlen = off + msg_hdr_sz(msg);
	th = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th)){
			pr_info("gro_header failed 1\n");
			goto out;
		}
	}
	/*
	thlen = msg_hdr_sz(th);
	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th)){
			pr_info("gro_header failed 2\n");
			goto out;
		}
	}*/

	skb_gro_pull(skb, thlen);
	len = skb_gro_len(skb);
	pr_info("head=%p\n",*head);
	for (; (p = *head); head = &p->next) {
		pr_info("p=%p, skb=%p\n", p, skb);
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;
		th2 = buf_msg(p);
		
		if ((msg_origport(th) ^ msg_origport(th2)) |
		    (msg_destport(th) ^ msg_destport(th2)) |
		    (msg_prevnode(th) ^ msg_prevnode(th2))) {
			NAPI_GRO_CB(p)->same_flow = 0;
			pr_info("packets are not for the same flow\n");
			pr_info("th oport=%u th2 oport=%u\n", msg_origport(th), msg_origport(th2));
			pr_info("th dport=%u th2 dport=%u\n", msg_destport(th), msg_destport(th2));
			pr_info("th pnode=0x%x th2 pnode=0x%x\n", msg_prevnode(th), msg_prevnode(th2));
			continue;
		}
		pr_info("goto found\n");
		goto found;
	}
	goto out_check_final;

found:
	flush = NAPI_GRO_CB(p)->flush;
	pr_info("flush is %d\n", flush);
	pr_info("Matching packets:\n");
	pr_info("th oport=%u th2 oport=%u\n", msg_origport(th), msg_origport(th2));
	pr_info("th dport=%u th2 dport=%u\n", msg_destport(th), msg_destport(th2));
	pr_info("th pnode=0x%x th2 pnode=0x%x\n", msg_prevnode(th), msg_prevnode(th2));

	pr_info("th seq=%d gro_len(p)=%d, napi count= %d th2 seq=%d\n", msg_seqno(th),
				skb_gro_len(p),NAPI_GRO_CB(p)->count, msg_seqno(th2));
	flush |= ((msg_seqno(th2) + NAPI_GRO_CB(p)->count) ^ msg_seqno(th));
	if (flush || skb_gro_receive(head, skb))
		goto out_check_final;
	p = *head;
	th2 = buf_msg(p);

out_check_final:
	flush = (msg_errcode(msg) != 0);
	
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush)){
		pr_info("packets are not for the same flow, or flush is set\n");
		pp = head;
	}

out:
	NAPI_GRO_CB(skb)->flush |= flush;
	pr_info("conn_gro_receive returns %p, head = %p, skb=%p\n", pp,
			head, skb);
	return pp;
}
static int conn_gro_complete(struct sk_buff *skb)
{
	struct tipc_msg *msg;
	__be32 newlen;

	msg = buf_msg(skb);
	newlen = skb->len - skb_network_offset(skb);
	pr_info("conn_gro_complete:update length to %d\n",newlen);
	msg_set_size(msg, newlen);
	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
	return 0;
}

struct net_offload conn_offload = {
	.callbacks = {
		.gro_receive = conn_gro_receive,
		.gro_complete = conn_gro_complete,
	},
};


/**
 *head: list of currently held packets
 *skb: the new packet
 */
static struct sk_buff **tipc_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct tipc_msg *msg;
	int flush = 0;
	unsigned int off;
	unsigned int hlen;
	struct tipc_msg *hdr;

	msg = buf_msg(skb);
/*
	off = skb_gro_offset(skb);
	hlen = off + msg_hdr_sz(msg);
	hdr = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, off)) {
		hdr = skb_gro_header_slow(skb, hlen, off);
		if (unlikely (!hdr)){
			pr_err("gro header creation failed\n");
			goto out;
		}
	}
	*/
	if (!msg_isdata(msg))
		goto out;
	pr_info("rcvd message with seqno %d\n", msg_seqno(msg));
	switch(msg_type(msg)) {
		case TIPC_CONN_MSG:
			pr_info("gro_receive for TIPC_CONN_MSG\n");
			pp = conn_offload.callbacks.gro_receive(head, skb);
			break;
		default:
		goto out;
		break;
	}
	/*Do stuff per msg_type here*/
	goto out;


out:
	NAPI_GRO_CB(skb)->flush |= flush;
	pr_info("tipc_gro_receive returns %p \n", pp  );
	pr_info("flush bits for skb is %d\n",NAPI_GRO_CB(skb)->flush);
	return pp;
}

static int tipc_gro_complete(struct sk_buff *skb)
{
	struct tipc_msg *msg;
	int err = -ENOSYS;
	msg = buf_msg(skb);
	pr_info("tipc_gro_complete for message type %d\n", msg_type(msg));
	if (!msg_isdata(msg)) {
		pr_err("non-data message GRO'd\n");
		dump_stack();
	}
	switch(msg_type(msg)){
		case TIPC_CONN_MSG:
			pr_info("gro_complete for TIPC_CONN_MSG\n");
			err = conn_offload.callbacks.gro_complete(skb);
			break;
		default:
		return 0;
		break;
	}
	return err;
}

static struct packet_offload tipc_packet_offload __read_mostly = {
		.type = cpu_to_be16(ETH_P_TIPC),
		.callbacks = {
//			.gso_send_check = tipc_gso_send_check,
//			.gso_segment = tipc_gso_segment,
			.gro_receive = tipc_gro_receive,
			.gro_complete = tipc_gro_complete,
		},
};
/**
 * tipc_eth_media_start - activate Ethernet bearer support
 *
 * Register Ethernet media type with TIPC bearer code.  Also register
 * with OS for notifications about device state changes.
 */
int tipc_eth_media_start(void)
{
	int res;

	if (eth_started)
		return -EINVAL;

	res = tipc_register_media(&eth_media_info);
	if (res)
		return res;

	dev_add_offload(&tipc_packet_offload);

	res = register_netdevice_notifier(&notifier);
	if (!res)
		eth_started = 1;
	return res;
}

/**
 * tipc_eth_media_stop - deactivate Ethernet bearer support
 */
void tipc_eth_media_stop(void)
{
	if (!eth_started)
		return;

	flush_scheduled_work();
	unregister_netdevice_notifier(&notifier);
	eth_started = 0;
}
