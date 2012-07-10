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
#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/kthread.h>

#define DEFAULT_MC_GROUP "228.0.0.1"
#define MAX_IP_BEARERS 1
#define IP_STR_MAX 64
#define IP_ADDR_OFFSET	4
#define TIPC_UDPPORT 2048


/**
 *
 */
struct udp_bearer {
	struct tipc_bearer *bearer;
	struct socket *socket;
	struct task_struct *task_send;
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
	.type_id	= TIPC_MEDIA_TYPE_IP,
	.name		= "udp"
};


static void udp_media_addr_set(struct tipc_media_addr *a,
			       struct sockaddr_in *sin)
{
	if(sin->sin_family != AF_INET) {
	//TODO: ndisc code need to be updated for v6.
	//the bearer level orig address field is too small
	//tipc_media_addr_size also.	
		pr_err("AF not supported\n");
		return;
	}
	a->media_id = TIPC_MEDIA_TYPE_IP;
	//a should now contain:
	//AF_INET/ipv4addr
	memcpy(a->value, &sin->sin_addr.s_addr, sizeof(struct in_addr));
	a->broadcast = ((sin->sin_addr.s_addr & 0xE0) == 0xE0);
}
struct udp_skb_meta{
	struct tipc_media_addr *dest;
	struct udp_bearer *ub_ptr;
};
static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
//	struct udp_bearer *ub_ptr = &udp_bearers[0];
	struct udp_skb_meta *meta;

#define MAX_SEND_QUEUE 256
	spin_lock_bh(&send_queue.lock);
	if (skb_queue_len(&send_queue) >= MAX_SEND_QUEUE) {
		spin_unlock_bh(&send_queue.lock);
		pr_err("tipc: udp send buffer overrun\n");
		//TODO: set bearer congested/blocked
		return 0;
	}
	meta = skb->cb;
	meta->dest = dest;
	meta->ub_ptr = tb_ptr->usr_handle;
	__skb_queue_head(&send_queue, skb);
	spin_unlock_bh(&send_queue.lock);
	wake_up_interruptible(&send_queue_wait);
	return 0;

/*
	memset(&msg,0,sizeof(struct msghdr));
	//TODO: need a ringbuffer here, defer sending to a kthread
	
	dst.sin_family = AF_INET;
	memcpy(&dst.sin_addr.s_addr, dest->value, sizeof(struct in_addr));
	dst.sin_port = TIPC_UDPPORT;
//	dst.sin_port = IPPROTO_TIPC;
	printk("send packet (%d bytes) to 0x%x\n", skb->len, 
			dst.sin_addr.s_addr);
	iov.iov_base = skb->data;
	iov.iov_len = skb->len;
	msg.msg_name = &dst;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
*/
//	err = kernel_sendmsg(ub_ptr->socket, &msg, &iov, 1, skb->len);
//	printk("sendmsg returned %d\n",err);
	//TODO: handle congestion/block bearer
//	return err;
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
	printk("tipc: woke up tipc_udp_send, got %d packets to send\n",
		skb_queue_len(&send_queue));

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
		msg.msg_control = NULL;	//XXX
		msg.msg_controllen = 0;	//XXX
		msg.msg_flags = 0;	//XXX
		printk("send packet (%d bytes) to 0x%x\n", skb->len, 
			dst.sin_addr.s_addr);
		err = kernel_sendmsg(meta->ub_ptr->socket, &msg, &iov, 1, skb->len);
		printk("sendmsg returned %d\n",err);
		
		//TODO: When is skb freed?
	}
	goto again;
}

static void tipc_udp_recv(struct sock* sk, int bytes)
{
	struct sk_buff *skb;
	int err;
	printk("sk data available\n");
	skb = skb_recv_datagram(sk, 0, 1, &err);
	if (err == -EAGAIN)
		return;
	printk("deliver to link layer\n");
	tipc_recv_msg(skb, udp_bearers[0].bearer);
}


struct enable_bearer_work
{
	struct work_struct ws;
	struct udp_bearer *ub_ptr;
	struct sockaddr_in addr;
};

static void enable_bearer_wh(struct work_struct *ws)
{
	struct ip_mreq mreq;
	struct sockaddr_in sin;
	struct udp_bearer *ub_ptr;
	int err;
	struct enable_bearer_work *work;

	work = container_of(ws, struct enable_bearer_work, ws);
	ub_ptr = work->ub_ptr;

//	err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &ub_ptr->socket);
	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->socket);


	BUG_ON(err);
	memcpy(&mreq.imr_multiaddr.s_addr, &udp_media_info.bcast_addr.value,
	       sizeof(struct in_addr));
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	err = kernel_setsockopt(ub_ptr->socket, IPPROTO_IP,
				IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));
	BUG_ON(err);

	err = kernel_bind(ub_ptr->socket, (struct sockaddr*)&work->addr,
			  sizeof(struct sockaddr_in));
	printk("bound addr\n");
	BUG_ON(err);

	ub_ptr->task_send = kthread_run(tipc_udp_send, NULL, "tipc_udp_send");
	ub_ptr->socket->sk->sk_data_ready = tipc_udp_recv;
	udp_started = 1;
	kfree(work);
}

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct udp_bearer *ub_ptr = &udp_bearers[0];
	struct enable_bearer_work *ws;
	char addr[16];
	int ret;

	printk("enable bearer:> %s\n",tb_ptr->name);
	ws = kmalloc(sizeof(struct enable_bearer_work), GFP_ATOMIC);
	BUG_ON(!ws);
	INIT_WORK(&ws->ws, enable_bearer_wh);

	ret = sscanf(tb_ptr->name, "udp:%s", addr);
	if (ret == 0)
		goto fail;
	ws->addr.sin_addr.s_addr = in_aton(addr);

	printk("addr: %s\n",addr);
	ws->addr.sin_family = AF_INET;
	ws->addr.sin_port = htons(TIPC_UDPPORT);
	skb_queue_head_init(&send_queue);

	ws->ub_ptr = ub_ptr;
	printk("schedule work\n");
	schedule_work(&ws->ws);
	tb_ptr->usr_handle = ub_ptr;
	tb_ptr->mtu = 1500;
	tb_ptr->blocked = 0;
	udp_media_addr_set(&tb_ptr->addr, &ws->addr);
	
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
	struct sockaddr_in *sin;
	char tmp[255];
	sin = a->value;
/*
	if (inet_ntop(sin->sin_family, sin->sin_addr, tmp, 255) == NULL) {
		pr_err("inet_ntop failed\n");
		return 1; //TODO: -EINVAL??
	}
*/
	snprintf(buf, size, "%pI4 port:%u", sin->sin_addr.s_addr,
		 sin->sin_port);
//	snprintf(buf, size, "%s port:%u",tmp, sin->sin_port);
	printk("udp_addr2str( ) == %s\n",buf);
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
	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_IP)
		return 1; //TODO: -EINVAL?
	//TODO:FIXME
	udp_media_addr_set(a, msg_area + IP_ADDR_OFFSET);
	return 0;
}

static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area)
{
	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_IP)
		return 1;
	udp_media_addr_set(a, msg_area + IP_ADDR_OFFSET);
	return 0;
}

int tipc_udp_media_start(void)
{
	int res;
	res = in_aton(DEFAULT_MC_GROUP);
	memcpy(&udp_media_info.bcast_addr.value, &res, sizeof(res));
	udp_media_info.bcast_addr.media_id = TIPC_MEDIA_TYPE_IP;
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
