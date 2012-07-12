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
	struct socket *socket;
	struct task_struct *task_send;
	struct sockaddr_in listen;
	struct sockaddr_in ndisc;
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
static struct udp_bearer udp_bearers[MAX_IP_BEARERS];
static struct socket *multicast_socket;
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
			       struct in_addr *addr)
{
	a->media_id = TIPC_MEDIA_TYPE_UDP;
	//a should now contain:
	//AF_INET/ipv4addr
	memcpy(a->value, addr, sizeof(struct in_addr));
	if (ipv4_is_multicast(addr)) {
		printk("set bcast bit for address 0x%x\n", *addr);
		a->broadcast = 1;
	} else {
		a->broadcast = 0;
	}
}
struct udp_skb_meta{
	struct tipc_media_addr *dest;
	struct udp_bearer *ub_ptr;
};

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	struct udp_skb_meta *meta;
	struct sk_buff *clone;

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
	meta = clone->cb;
	meta->dest = dest;
	meta->ub_ptr = tb_ptr->usr_handle;
	__skb_queue_head(&send_queue, clone);
	spin_unlock_bh(&send_queue.lock);
	wake_up_interruptible(&send_queue_wait);
	return 0;
}

static int tipc_udp_send(void *param)
{
	struct msghdr msg;
	struct kvec iov;
	struct sockaddr_in dst;
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

		dst.sin_family = AF_INET;
		dst.sin_port = htons(TIPC_UDPPORT);
		memcpy(&dst.sin_addr.s_addr, meta->dest, sizeof(struct in_addr));
		iov.iov_base = skb->data;
		iov.iov_len = skb->len;
		msg.msg_iov = &iov;
		msg.msg_name = &dst;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		if (ipv4_is_multicast(&dst.sin_addr.s_addr))
			err = kernel_sendmsg(multicast_socket, &msg, &iov,
					     1,skb->len);
		else
			err = kernel_sendmsg(meta->ub_ptr->socket, &msg, &iov,
					     1, skb->len);
		//TODO: When is skb freed?
	}
	goto again;
}

static void tipc_udp_recv(struct sock *sk, int bytes)
{
	struct sk_buff *skb;
	int err;
	skb = skb_recv_datagram(sk, 0, 1, &err);
	if (err == -EAGAIN)
		return;
	skb_pull(skb, sizeof(struct udphdr));
	print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS, 
	16, 1, skb->data, skb->len, true);
	skb->next = NULL;
	tipc_recv_msg(skb, udp_bearers[0].bearer);
}

struct enable_bearer_work
{
	struct work_struct ws;
	struct udp_bearer *ub_ptr;
	struct sockaddr_in addr;
	struct sockaddr_in ndisc;
};

static void enable_bearer_wh(struct work_struct *ws)
{
	struct ip_mreq mreq;
	struct sockaddr_in sin;
	struct udp_bearer *ub_ptr;
	static const int mloop = 0;
	int err;
	struct enable_bearer_work *work;

	work = container_of(ws, struct enable_bearer_work, ws);
	ub_ptr = work->ub_ptr;
	if (!udp_started) { //TODO: break this out to a separate function
		err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &multicast_socket);
		BUG_ON(err);
		memcpy(&mreq.imr_multiaddr.s_addr,
		       &udp_media_info.bcast_addr.value,
		       sizeof(struct in_addr));
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		err = kernel_setsockopt(multicast_socket, IPPROTO_IP,
					IP_ADD_MEMBERSHIP,
					(char*)&mreq, sizeof(mreq));
		BUG_ON(err);

		err = kernel_setsockopt(multicast_socket, IPPROTO_IP,
					IP_MULTICAST_LOOP, (char*) &mloop, sizeof(mloop));
		BUG_ON(err);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(TIPC_UDPPORT);
		sin.sin_addr.s_addr = mreq.imr_multiaddr.s_addr;
		err = kernel_bind(multicast_socket, (struct sockaddr*)&sin,
			  	  sizeof(struct sockaddr_in));
		BUG_ON(err);
		multicast_socket->sk->sk_data_ready = tipc_udp_recv;
	}
	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->socket);
	BUG_ON(err);

	err = kernel_bind(ub_ptr->socket, (struct sockaddr*)&work->addr,
			  sizeof(struct sockaddr_in));
	BUG_ON(err);

	ub_ptr->task_send = kthread_run(tipc_udp_send, NULL, "tipc_udp_send");
	ub_ptr->socket->sk->sk_data_ready = tipc_udp_recv;
	udp_started = 1;
	kfree(work);
}

static void parse_udpargs(char *arg, char *addr, char *ndisc, __be16 *port)
{
	char *start;
	char *end;
	printk("arg= %s\n",arg);
	start = strchr(arg, ':') + 1;
	end = strchr(start, ':');
	*end = 0;
	strcpy(addr, start);
	printk("parsed addr= %s\n",addr);
	
	start = end + 1;
	end = strchr(start, ':');
	*end = 0;
	*port = simple_strtoull(start, NULL, 10);
	printk("parsed and converted port= %u\n", *port);

	start = end + 1;
	strcpy(ndisc, start);
	printk("parsed ndisc address = %s\n", ndisc);
}

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct udp_bearer *ub_ptr = &udp_bearers[0];
	struct enable_bearer_work *ws;
	char addr[16];
	char ndisc[16];
	__be16	port = 0;
	int ret;

	printk("enable bearer:> %s\n",tb_ptr->name);
	ws = kmalloc(sizeof(struct enable_bearer_work), GFP_ATOMIC);
	BUG_ON(!ws);
	INIT_WORK(&ws->ws, enable_bearer_wh);

//	ret = sscanf(tb_ptr->name, "udp:%s:%hd:%s", addr, &port, ndisc);
	parse_udpargs(tb_ptr->name, addr, ndisc, &port);

//	FIXME: store port and ndisc info in bearer
/*
	if (ret == 0) {
		//TODO: try to fetch interface name after udp:
		goto fail;
	}
*/
	if (!port)
		port = TIPC_UDPPORT;

	ws->addr.sin_family = AF_INET;
	ws->addr.sin_addr.s_addr = in_aton(addr);
	printk("addr: %s port: %u\n",addr, port);
	ws->addr.sin_port = htons(port);

	ws->ndisc.sin_family = AF_INET;
	ws->ndisc.sin_addr.s_addr = in_aton(ndisc);
	printk("ndisc: %s\n", ndisc);
	ws->ndisc.sin_port = htons(port);

	skb_queue_head_init(&send_queue);

	ws->ub_ptr = ub_ptr;
	printk("schedule work\n");
	schedule_work(&ws->ws);
	tb_ptr->usr_handle = ub_ptr;
	ub_ptr->bearer = tb_ptr;
	tb_ptr->mtu = 1500;
	tb_ptr->blocked = 0;
	udp_media_addr_set(&tb_ptr->addr, &ws->addr.sin_addr.s_addr);
	
//	ub_ptr->socket->sk->sk_data_ready = tipc_udp_recv;
	//TODO: stringify macro on fn name

	return 0;
fail:
	kfree(ws);
	return -EINVAL;
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
 	__be32 ip = in_aton(buf);
	memcpy(a->value, &ip, sizeof(ip));
	return 0;
}

static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area)
{
        print_hex_dump(KERN_DEBUG, "msg_area[TIPC_MEDIA_TYPE_OFFSET] (+4) == ", DUMP_PREFIX_ADDRESS, 
        16, 1, &(msg_area[TIPC_MEDIA_TYPE_OFFSET]), 4, true);

	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_UDP){
		printk("media addr != UDP\n");
		return 1; //TODO: -EINVAL?
	}
        print_hex_dump(KERN_DEBUG, "msg_area+IP_ADDR_OFFSET] (+8) == ", DUMP_PREFIX_ADDRESS, 
        16, 1, msg_area + IP_ADDR_OFFSET, 8, true);

	//TODO:FIXME
	udp_media_addr_set(a, msg_area + IP_ADDR_OFFSET);
	return 0;
}

static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area)
{
	memset(msg_area, 0, TIPC_MEDIA_ADDR_SIZE);
	msg_area[TIPC_MEDIA_TYPE_OFFSET] = TIPC_MEDIA_TYPE_UDP;
	memcpy(msg_area + IP_ADDR_OFFSET, a->value, sizeof(struct in_addr));
	return 0;
}

int tipc_udp_media_start(void)
{
	int res;
	res = in_aton(DEFAULT_MC_GROUP);
	memcpy(&udp_media_info.bcast_addr.value, &res, sizeof(res));
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
