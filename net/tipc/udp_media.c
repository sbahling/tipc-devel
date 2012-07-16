/*
 * net/tipc/udp_media.c: IP bearer support for TIPC
 *
 * Copyright (c) 2012, Ericsson AB
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
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>

#define DEFAULT_MC_GROUP "228.0.0.1"
#define MAX_IP_BEARERS 1
#define IP_STR_MAX 64
#define IP_ADDR_OFFSET	4
#define TIPC_UDPPORT 2048
#define MAX_SEND_QUEUE 256


/**
 *
 */
struct udp_bearer {
	struct tipc_bearer *bearer;
	struct socket *traffic;
	struct socket *mcast;
	struct task_struct *task_send;
	struct sockaddr_in ndisc;
	struct list_head next;
};

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest);
static int enable_bearer(struct tipc_bearer *tb_ptr);
static void disable_bearer(struct tipc_bearer *tb_ptr);
static int udp_addr2str(struct tipc_media_addr *a, char *buf, int size);
static int udp_str2addr(struct tipc_media_addr *a, char *buf);
static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area);
static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area);

static struct sk_buff_head send_queue;
static DECLARE_WAIT_QUEUE_HEAD(send_queue_wait);
//static struct udp_bearer udp_bearers[MAX_IP_BEARERS];
static LIST_HEAD(bearer_list);

static int udp_started;

static struct tipc_media udp_media_info = {
	.send_msg	= send_msg,
	.enable_bearer	= enable_bearer,
	.disable_bearer	= disable_bearer,
	.addr2str	= udp_addr2str,
	.str2addr	= udp_str2addr,
	.addr2msg	= udp_addr2msg,
	.msg2addr	= udp_msg2addr,
	.priority	= TIPC_DEF_LINK_PRI,
	.tolerance	= TIPC_DEF_LINK_TOL,
	.window		= TIPC_DEF_LINK_WIN,
	.type_id	= TIPC_MEDIA_TYPE_UDP,
	.name		= "udp"
};


static void udp_media_addr_set(struct tipc_media_addr *a,
			       struct sockaddr_in *addr)
{
	a->media_id = TIPC_MEDIA_TYPE_UDP;
	memcpy(a->value, addr, sizeof(struct sockaddr_in));
        print_hex_dump(KERN_DEBUG, "udp_media_addr_set: ", DUMP_PREFIX_ADDRESS, 
        16, 1, a->value, sizeof(struct sockaddr_in), true);

	if (ipv4_is_multicast(addr->sin_addr.s_addr)) {
		pr_debug("set bcast bit for address 0x%x\n", *addr);
		a->broadcast = 1;
	} else {
		a->broadcast = 0;
	}
}
struct udp_skb_meta{
	struct sockaddr_in *dst;
	struct udp_bearer *ub_ptr;
};

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	struct udp_skb_meta *meta;
	struct udp_bearer *ub_ptr;
	struct sk_buff *clone;
	struct tipc_media_addr *remote = dest;

	ub_ptr = tb_ptr->usr_handle;
	if(dest->broadcast == 1) {
		/*ndisc/bearer code assumes ndisc to go out on a media addr.
		workaround*/
		remote = &ub_ptr->ndisc;
	}

	if (!udp_started) {
		pr_err("tipc: udp is not started yet\n");
		return 0;
	}
	clone = skb_clone(skb, GFP_ATOMIC);
	spin_lock_bh(&send_queue.lock);
	if (skb_queue_len(&send_queue) >= MAX_SEND_QUEUE) {
		spin_unlock_bh(&send_queue.lock);
		pr_err("tipc: udp send buffer overrun\n");
		//TODO: set bearer congested/blocked
		return 0;
	}
	print_hex_dump(KERN_DEBUG, "queue sendmsg to addr: ", DUMP_PREFIX_ADDRESS, 
	        16, 1, remote, sizeof(struct sockaddr_in), true);

	meta = clone->cb;
	meta->dst = remote;
	meta->ub_ptr = ub_ptr;
	__skb_queue_head(&send_queue, clone);
	spin_unlock_bh(&send_queue.lock);
	wake_up_interruptible(&send_queue_wait);
	return 0;
}

static int tipc_udp_send(void *param)
{
	struct msghdr msg;
	struct kvec iov;
	struct sk_buff *skb;
	struct udp_skb_meta *meta;
	int err;

again:
	wait_event_interruptible(send_queue_wait,
				 (udp_started && 
				 !skb_queue_empty(&send_queue)) ||
				 kthread_should_stop());
	if(kthread_should_stop())
		return 0;

	while (!skb_queue_empty(&send_queue)) {
		memset(&msg,0,sizeof(struct msghdr));
		skb = skb_dequeue_tail(&send_queue);
		meta = skb->cb;

		print_hex_dump(KERN_DEBUG, "udp sendmsg to addr: ", DUMP_PREFIX_ADDRESS, 
	        16, 1, meta->dst, sizeof(struct sockaddr_in), true);
		iov.iov_base = skb->data;
		iov.iov_len = skb->len;
		msg.msg_iov = &iov;
		msg.msg_name = meta->dst;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		pr_debug("remote= 0x%x, port=%u\n",meta->dst->sin_addr.s_addr, meta->dst->sin_port);


/*
		if (ipv4_is_multicast(meta->dst->sin_addr.s_addr))
*/
			err = kernel_sendmsg(meta->ub_ptr->mcast, &msg, &iov,
					     1,skb->len);
/*
		else
			err = kernel_sendmsg(meta->ub_ptr->traffic, &msg, &iov,
					     1, skb->len);
*/
		//TODO: When is skb freed?
	}
	goto again;
}

static void tipc_udp_recv(struct sock *sk, int bytes)
{
	struct sk_buff *skb;
	struct udp_bearer *ub_ptr;
	int err;

	skb = skb_recv_datagram(sk, 0, 1, &err);
	if (err == -EAGAIN)
		return;
	skb_pull(skb, sizeof(struct udphdr));
	print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS, 
	16, 1, skb->data, skb->len, true);
	skb->next = NULL;
	/*TODO: how to fetch bearer reference from sk????*/
	ub_ptr = sk->sk_user_data;
	pr_debug("Packet receive,bearer ptr=0x%p bearer name: %s\n", 
		 ub_ptr, ub_ptr->bearer->name);
	BUG_ON(!ub_ptr);
	
	tipc_recv_msg(skb, ub_ptr->bearer);
}

struct enable_bearer_work
{
	struct work_struct ws;
	struct udp_bearer *ub_ptr;
};

static void enable_bearer_wh(struct work_struct *ws)
{
	struct ip_mreq mreq;
	struct sockaddr_in *listen;
	struct udp_bearer *ub_ptr;
	static const int mloop = 0;
	int err;
	struct enable_bearer_work *work;

	work = container_of(ws, struct enable_bearer_work, ws);
	ub_ptr = work->ub_ptr;
	kfree(work);

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->mcast);
	BUG_ON(err);
	ub_ptr->mcast->sk->sk_user_data = ub_ptr;
	pr_debug("set mcast sock private data = 0x%p\n", ub_ptr);
	if (ipv4_is_multicast(ub_ptr->ndisc.sin_addr.s_addr)) {
		pr_debug("joining multicast group\n");
		memcpy(&mreq.imr_multiaddr.s_addr,
		       &ub_ptr->ndisc.sin_addr.s_addr,
		       sizeof(struct in_addr));
	 /*TODO: join only mcgroup on the interface that work->addr belongs to*/
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		err = kernel_setsockopt(ub_ptr->mcast, IPPROTO_IP,
					IP_ADD_MEMBERSHIP,
					(char*)&mreq, sizeof(mreq));
		BUG_ON(err);
		err = kernel_setsockopt(ub_ptr->mcast, IPPROTO_IP,
					IP_MULTICAST_LOOP, (char*) &mloop, sizeof(mloop));
		BUG_ON(err);
		err = kernel_bind(ub_ptr->mcast, (struct sockaddr*)&ub_ptr->ndisc,
		  	  sizeof(struct sockaddr_in));
		BUG_ON(err);


	} else {
		pr_info("unicast discovery mode\n");
	}

	ub_ptr->mcast->sk->sk_data_ready = tipc_udp_recv;
	listen = &ub_ptr->bearer->addr;

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->traffic);
	BUG_ON(err);
	ub_ptr->traffic->sk->sk_user_data = ub_ptr;
	pr_debug("set traffic sock private data = 0x%p\n", ub_ptr);
	pr_debug("bind listen socket: 0x%x, port %u\n", 
		listen->sin_addr.s_addr, listen->sin_port);
	err = kernel_bind(ub_ptr->traffic, (struct sockaddr*)listen,
			  sizeof(struct sockaddr_in));
	BUG_ON(err);

	ub_ptr->task_send = kthread_run(tipc_udp_send, NULL, "tipc_udp_send");
	ub_ptr->traffic->sk->sk_data_ready = tipc_udp_recv;
	udp_started = 1;
}

static int parse_udpargs(char *arg, char *addr, char *ndisc, __be16 *port)
{
	char tmp[TIPC_MAX_BEARER_NAME];
	char *start;
	char *end;

	pr_debug("arg= %s\n",arg);
	strncpy(tmp, arg, TIPC_MAX_BEARER_NAME);
	start = strchr(tmp, ':') + 1;
	end = strchr(start, ':');
	if (end)
		*end = 0;
	strcpy(addr, start);
	pr_debug("parsed addr= %s\n",addr);
	if (!end)
		return 0;

	start = end + 1;
	end = strchr(start, ':');
	if (end)
		*end = 0;
	*port = simple_strtoull(start, NULL, 10);
	pr_debug("parsed and converted port= %u\n", *port);
	if (!end)
		return 0;

	start = end + 1;
	strcpy(ndisc, start);
	pr_debug("parsed ndisc address = %s\n", ndisc);
}

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
//	struct udp_bearer *ub_ptr = &udp_bearers[0];
	struct udp_bearer *ub_ptr;
	struct enable_bearer_work *ws;
	char addr[16];
	char ndisc[16] = DEFAULT_MC_GROUP;
	__be16	port = TIPC_UDPPORT;
	struct sockaddr_in listen;
	struct list_head *entry;
	int ret;

/*
	list_for_each(entry, &bearer_list) {
		ub_ptr = list_entry(entry, struct udp_bearer, next);
	}
*/
	ub_ptr = kmalloc(sizeof(struct udp_bearer), GFP_ATOMIC);
	BUG_ON(!ub_ptr);

	parse_udpargs(tb_ptr->name, addr, ndisc, &port);
	skb_queue_head_init(&send_queue);
	tb_ptr->usr_handle = ub_ptr;
	ub_ptr->bearer = tb_ptr;
	tb_ptr->mtu = 1500;
	tb_ptr->blocked = 0;
	ub_ptr->ndisc.sin_family = AF_INET;
	ub_ptr->ndisc.sin_addr.s_addr = in_aton(ndisc);
	ub_ptr->ndisc.sin_port = htons(port);

	listen.sin_family = AF_INET;
	listen.sin_addr.s_addr = in_aton(addr);
	listen.sin_port = htons(port);

	pr_debug("listen: %s port: %u\n",addr, port);
	pr_debug("ndisc: %s port: %u\n", ndisc, port);

	pr_debug("enable bearer:> %s\n",tb_ptr->name);
	ws = kmalloc(sizeof(struct enable_bearer_work), GFP_ATOMIC);
	BUG_ON(!ws);
	INIT_WORK(&ws->ws, enable_bearer_wh);
	ws->ub_ptr = ub_ptr;

	print_hex_dump(KERN_DEBUG, "enable bearer addr: ", DUMP_PREFIX_ADDRESS, 
	16, 1, &listen, sizeof(struct sockaddr_in), true);
	udp_media_addr_set(&tb_ptr->addr, &listen);

	pr_debug("schedule work\n");
	schedule_work(&ws->ws);
	pr_debug("add to list\n");
	list_add_tail(&ub_ptr->next, &bearer_list);

	return 0;
}

static void cleanup_bearer(struct work_struct *work)
{
}

static void disable_bearer(struct tipc_bearer *tb_ptr)
{
}

static int udp_addr2str(struct tipc_media_addr *a, char *buf, int size)
{
	snprintf(buf, size, "%pI4", a->value);
	return 0;
}

static int udp_str2addr(struct tipc_media_addr *a, char *buf)
{
	//FIXME:broken
 	__be32 ip = in_aton(buf);
	memcpy(a->value, &ip, sizeof(ip));
	return 0;
}

static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area)
{
//	struct sockaddr_in sin;
        print_hex_dump(KERN_DEBUG, "msg_area[TIPC_MEDIA_TYPE_OFFSET] (+4) == ", 
				DUMP_PREFIX_ADDRESS, 
			        16, 1, &(msg_area[TIPC_MEDIA_TYPE_OFFSET]), 4, true);

	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_UDP){
		pr_debug("media addr != UDP\n");
		return 1; //TODO: -EINVAL?
	}

        print_hex_dump(KERN_DEBUG, "msg_area+IP_ADDR_OFFSET] (+8) == ", DUMP_PREFIX_ADDRESS, 
        16, 1, msg_area + IP_ADDR_OFFSET, 8, true);

	udp_media_addr_set(a,msg_area+IP_ADDR_OFFSET);

	//TODO:FIXME
//	sin.sin_family = AF_INET;
//	memcpy(&sin.sin_addr.s_addr, msg_area + IP_ADDR_OFFSET, sizeof(struct in_addr));
//	memcpy(&sin.sin_port, msg_area + IP_ADDR_OFFSET + sizeof(struct in_addr), sizeof(__be16));
//	udp_media_addr_set(a, msg_area + IP_ADDR_OFFSET);
//	udp_media_addr_set(a, &sin);
	return 0;
}

static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area)
{
	/*TODO: rewrite this to take bearer pointer instead of addr.
	  Eth media need to be changed aswell. (make a prereq patch for this)
	  the name is misleading, what it actually does is to copy the address used for 
	  ndisc messages to msg_area*/
	struct tipc_bearer *tb;
	struct udp_bearer *ub;
	
	tb = container_of(a, struct tipc_bearer, addr);
	BUG_ON(!tb);
	pr_debug("got reference to %s\n", tb->name);
	ub = tb->usr_handle;
	print_hex_dump(KERN_DEBUG, "udp_addr2msg: ", DUMP_PREFIX_ADDRESS, 
                16, 1, &ub->ndisc, sizeof(struct sockaddr_in), true);

	memset(msg_area, 0, TIPC_MEDIA_ADDR_SIZE);
	msg_area[TIPC_MEDIA_TYPE_OFFSET] = TIPC_MEDIA_TYPE_UDP;
	memcpy(msg_area + IP_ADDR_OFFSET, a->value, sizeof(struct sockaddr_in));
//	memcpy(msg_area + IP_ADDR_OFFSET, a->value, sizeof(struct in_addr) + sizeof(__be16));
//	memcpy(msg_area + IP_ADDR_OFFSET, &ub->ndisc.sin_addr.s_addr, sizeof(struct in_addr));
//	memcpy(msg_area + IP_ADDR_OFFSET + sizeof(struct in_addr), &ub->ndisc.sin_port, sizeof(__be16));
	return 0;
}

int tipc_udp_media_start(void)
{
	int res;
	res = in_aton(DEFAULT_MC_GROUP);
	/*Dont fill in bcast_addr.value, this is bearer specific for UDP*/
	udp_media_info.bcast_addr.media_id = TIPC_MEDIA_TYPE_UDP;
	udp_media_info.bcast_addr.broadcast = 1;
	//IP bearers use per-bearer multicast group instead	
	res = tipc_register_media(&udp_media_info);
	if (res)
		return res;

	return res;
}

void tipc_udp_media_stop(void)
{
}
