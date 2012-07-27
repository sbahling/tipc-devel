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
#include <linux/inetdevice.h>

#define IP_ADDR_OFFSET	4
#define MAX_SEND_QUEUE 256
#define UDP_PORT_BASE	50000
#define UDP_MCAST_PREFIX "228.0."
#define TIPC_UDP_CB(skb)	(*(struct udp_skb_parms*)&((skb)->cb))
#define TIPC_UDP_BEARER(skb)	(TIPC_UDP_CB(skb).ub_ptr)
#define TIPC_UDP_DST(skb)	(&TIPC_UDP_CB(skb).dst)
extern int tipc_net_id;

struct udp_skb_parms{
	struct sockaddr_in dst;
	struct udp_bearer *ub_ptr;
};

/**
 * struct udp_bearer - 
 * @bearer:	associated generic tipc bearer
 * @listen:	bearer listener socket
 * @transmit:	transmit socket
 * @discovery:	discovery socket address
 * @next:	list pointer
 * @work:	used to schedule deferred work on a bearer
 */
struct udp_bearer {
	atomic_t enabled;
	struct tipc_bearer *bearer;
	struct socket *listen;
	struct socket *transmit;
	struct sockaddr_in discovery;
	struct list_head next;
	struct work_struct work;
};

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest);
static int enable_bearer(struct tipc_bearer *tb_ptr);
static void disable_bearer(struct tipc_bearer *tb_ptr);
static int udp_addr2str(struct tipc_media_addr *a, char *buf, int size);
static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area);
static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area);

static struct sk_buff_head send_queue;
static DECLARE_WAIT_QUEUE_HEAD(send_queue_wait);
static LIST_HEAD(bearer_list);
static struct task_struct *task_send;
static atomic_t udp_started;

static struct tipc_media udp_media_info = {
	.send_msg	= send_msg,
	.enable_bearer	= enable_bearer,
	.disable_bearer	= disable_bearer,
	.addr2str	= udp_addr2str,
	.str2addr	= NULL,
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
	if (ipv4_is_multicast(addr->sin_addr.s_addr))
		a->broadcast = 1;
	else
		a->broadcast = 0;
}

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	struct udp_bearer *ub_ptr;
	struct sk_buff *clone;
	struct tipc_media_addr *remote = dest;

	ub_ptr = tb_ptr->usr_handle;
	/*The ndisc/bearer code assumes that tipc bcast packets go out on a 
	  media specific addr, point it to a bearer specific one instead*/
	if(dest->broadcast == 1)
		remote =(struct tipc_media_addr*) &ub_ptr->discovery;

	if (!atomic_read(&ub_ptr->enabled)) {
		pr_err("tipc: udp bearer is not started yet\n");
		return 0;
	}
	clone = skb_clone(skb, GFP_ATOMIC);
	spin_lock_bh(&send_queue.lock);
	if (skb_queue_len(&send_queue) >= MAX_SEND_QUEUE) {
		spin_unlock_bh(&send_queue.lock);
		pr_debug("tipc: udp send buffer overrun, block bearer\n");
		tb_ptr->blocked = 1;
		return 0;
	}
	memcpy(TIPC_UDP_DST(clone), remote, sizeof(struct sockaddr_in));
	TIPC_UDP_BEARER(clone) = ub_ptr;
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
	int err;

again:
	wait_event_interruptible(send_queue_wait,
				 !skb_queue_empty(&send_queue) ||
				 kthread_should_stop());
	if(kthread_should_stop())
		return 0;
	while (!skb_queue_empty(&send_queue)) {
		memset(&msg,0,sizeof(struct msghdr));
		skb = skb_dequeue_tail(&send_queue);
		iov.iov_base = skb->data;
		iov.iov_len = skb->len;
		msg.msg_iov = (struct iovec*) &iov;
		msg.msg_name = TIPC_UDP_DST(skb);
		msg.msg_namelen = sizeof(struct sockaddr_in);
		err = kernel_sendmsg(TIPC_UDP_BEARER(skb)->transmit, &msg,
				     &iov, 1,skb->len);
		if (unlikely(err < 0))
			pr_err("sendmsg on bearer %s failed with %d\n",
			       TIPC_UDP_BEARER(skb)->bearer->name, err);
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
	skb->next = NULL;
	ub_ptr = sk->sk_user_data;
	WARN_ON(!ub_ptr);

	if (atomic_read(&ub_ptr->enabled))
		tipc_recv_msg(skb, ub_ptr->bearer);
	else
		kfree_skb(skb);
}

/**
 * enable_bearer_wh - deferred udp bearer initialization
 * @work:	work struct holding the udp bearer pointer
 * 
 * create and initialize the listen and transmit udp sockets
 */
static void enable_bearer_wh(struct work_struct *work)
{
	struct ip_mreq mreq;
	struct sockaddr_in *listen;
	struct udp_bearer *ub_ptr;
	static const int mloop = 0;
	int err;

	ub_ptr = container_of(work, struct udp_bearer, work);
	listen = (struct sockaddr_in*) &ub_ptr->bearer->addr;
	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->listen);
	BUG_ON(err);
	err = kernel_bind(ub_ptr->listen, (struct sockaddr*)listen,
			  sizeof(struct sockaddr_in));
	WARN_ON(err);

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->transmit);
	BUG_ON(err);

	if (ipv4_is_multicast(ub_ptr->discovery.sin_addr.s_addr)) {
		memcpy(&mreq.imr_multiaddr.s_addr,
		       &ub_ptr->discovery.sin_addr.s_addr,
		       sizeof(struct in_addr));
		mreq.imr_interface.s_addr = listen->sin_addr.s_addr;
		err = kernel_setsockopt(ub_ptr->transmit, IPPROTO_IP,
					IP_ADD_MEMBERSHIP,
					(char*)&mreq, sizeof(mreq));
		WARN_ON(err);
		err = kernel_setsockopt(ub_ptr->transmit, IPPROTO_IP,
					IP_MULTICAST_LOOP, (char*) &mloop, sizeof(mloop));
		WARN_ON(err);
		err = kernel_bind(ub_ptr->transmit,
				  (struct sockaddr*)&ub_ptr->discovery,
		  		  sizeof(struct sockaddr_in));
		WARN_ON(err);
	}
	ub_ptr->transmit->sk->sk_data_ready = tipc_udp_recv;
	ub_ptr->listen->sk->sk_data_ready = tipc_udp_recv;
	ub_ptr->transmit->sk->sk_user_data = ub_ptr;
	ub_ptr->listen->sk->sk_user_data = ub_ptr;
	atomic_set(&ub_ptr->enabled, 1);
}

/**
 *
 */
static int validate_ipstr(char *ip)
{
	unsigned b1, b2, b3, b4;
	unsigned char c;

	if (sscanf(ip, "%3u.%3u.%3u.%3u%c", &b1, &b2, &b3, &b4, &c) != 4)
		return -EINVAL;
	if ((b1 | b2 | b3 | b4) > 255)
		return -EINVAL;
	if (strspn(ip, "0123456789.") < strlen(ip))
		return -EINVAL;
	return 1;
}

/**
 * getopt - deconstruct colon separated parameter string
 * @str:	parameter string
 * @opt:	output parameter
 * 
 * opt is set to the first parameter value in str
 * returns the length of opt, including \0
 */
static int getopt(char *str, char **opt)
{
	char *end;
	
	if(*str == '\0')
		return 0;
	*opt = str;
	end = strchr(str, ':');
	if (end)
		*end = '\0';
	return strlen(*opt) + 1;
}

/**
 * get_udpopts - parse udp bearer configuration
 * @arg:	bearer configuration string, including media name
 * @local:	output struct holding local ip/port
 * @remote:	output struct holding remote ip/port
 */
static int get_udpopts(char *arg, struct sockaddr_in *local, struct sockaddr_in *remote)
{
	char *opt = NULL;
	char str[TIPC_MAX_BEARER_NAME];
	int i;
	unsigned long port;
	int len = 0;
	char opt_default[16];

	local->sin_family = AF_INET;
	remote->sin_family = AF_INET;
	strncpy(str, arg, TIPC_MAX_BEARER_NAME);
	/*Skip media name*/
	len += getopt(str, &opt);
	/*Get the local address*/
	len += getopt(str + len, &opt);
	if (validate_ipstr(opt) == -EINVAL)
		return -EINVAL;
	local->sin_addr.s_addr = in_aton(opt);

	/*Optionally get the local port, or use default*/
	port = UDP_PORT_BASE + tipc_net_id;
	if ((i = getopt(str + len, &opt))) {
		port = simple_strtoul(opt, NULL, 10);
		if (port == 0 || port > 65535)
			return -EINVAL;
		len += i;
	}
	local->sin_port = htons(port);

	/*Optionally get the discovery address,
	  or use generated one based on network id*/
	sprintf(opt_default, UDP_MCAST_PREFIX"%u.%u",
		(tipc_net_id >> 8), (tipc_net_id & 0xFF));
	opt = opt_default;
	len += getopt(str + len, &opt);
	if (validate_ipstr(opt) == -EINVAL)
		return -EINVAL;
	remote->sin_addr.s_addr = in_aton(opt);

	/*Optionally get the remote port, or use default*/
	port = UDP_PORT_BASE + tipc_net_id;
	if ((i = getopt(str + len, &opt))) {
		port = simple_strtoul(opt, NULL, 10);
		if (0 == port || port > 65535)
			return -EINVAL;
	}
	remote->sin_port = htons(port);

	return 0;
}

/**
 * enable_bearer - callback to create a new udp bearer instance
 * @tb_ptr:	pointer to generic tipc_bearer
 *
 * validate the bearer parameters and perform basic initialization of the 
 * udp_bearer, the kernel socket setup is deferred
 */
static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct udp_bearer *ub_ptr;
	struct sockaddr_in listen;

	ub_ptr = kmalloc(sizeof(struct udp_bearer), GFP_ATOMIC);
	BUG_ON(!ub_ptr);

	if (get_udpopts(tb_ptr->name, &listen, &ub_ptr->discovery) == -EINVAL) {
		pr_debug("failed to parse udp options\n");
		kfree(ub_ptr);
		return -EINVAL;
	}
	if(!ip_dev_find(&init_net, listen.sin_addr.s_addr)){
		pr_err("Invalid address\n");
			return -ENODEV;
	}

	atomic_set(&ub_ptr->enabled, 0);
	tb_ptr->usr_handle = ub_ptr;
	ub_ptr->bearer = tb_ptr;
	tb_ptr->mtu = 1500;
	tb_ptr->blocked = 0;
	pr_debug("enable bearer:> %s\n",tb_ptr->name);
	INIT_WORK(&ub_ptr->work, enable_bearer_wh);

	print_hex_dump(KERN_DEBUG, "enable bearer addr: ", DUMP_PREFIX_ADDRESS, 
	16, 1, &listen, sizeof(struct sockaddr_in), true);
	udp_media_addr_set(&tb_ptr->addr, &listen);

	pr_debug("schedule work\n");
	schedule_work(&ub_ptr->work);
	pr_debug("add to list\n");
	list_add_tail(&ub_ptr->next, &bearer_list);

	return 0;
}

static void cleanup_bearer(struct work_struct *work)
{
	struct udp_bearer *ub_ptr;

	ub_ptr = container_of(work, struct udp_bearer, work);
	ub_ptr->bearer = NULL;
	sock_release(ub_ptr->listen);
	sock_release(ub_ptr->transmit);
	kfree(ub_ptr);
}

static void disable_bearer(struct tipc_bearer *tb_ptr)
{
	struct udp_bearer *ub_ptr;

	ub_ptr = (struct udp_bearer *)tb_ptr->usr_handle;
	INIT_WORK(&ub_ptr->work, cleanup_bearer);
	atomic_set(&ub_ptr->enabled, 0);
	schedule_work(&ub_ptr->work);
}

static int udp_addr2str(struct tipc_media_addr *a, char *buf, int size)
{
	snprintf(buf, size, "%pI4", a->value);
	return 0;
}

static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area)
{
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in*) (msg_area + IP_ADDR_OFFSET);

	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_UDP){
		pr_debug("media addr != UDP\n");
		return 1; //TODO: -EINVAL?
	}
	udp_media_addr_set(a, sin);
	return 0;
}

static int udp_addr2msg(struct tipc_media_addr *a, char *msg_area)
{
	memset(msg_area, 0, TIPC_MEDIA_ADDR_SIZE);
	msg_area[TIPC_MEDIA_TYPE_OFFSET] = TIPC_MEDIA_TYPE_UDP;
	memcpy(msg_area + IP_ADDR_OFFSET, &a->value, sizeof(struct sockaddr_in));
	return 0;
}

int tipc_udp_media_start(void)
{
	int res;

	if (atomic_read(&udp_started))
		return -EINVAL;
	/*Dont fill in bcast_addr.value, this is bearer specific for IP/UDP*/
	udp_media_info.bcast_addr.media_id = TIPC_MEDIA_TYPE_UDP;
	udp_media_info.bcast_addr.broadcast = 1;
	res = tipc_register_media(&udp_media_info);
	if (res)
		return res;
	skb_queue_head_init(&send_queue);
	task_send = kthread_run(tipc_udp_send, NULL, "tipc_udp_send");
	if (IS_ERR(task_send))
		return PTR_ERR(task_send);
	atomic_set(&udp_started, 1);
	return res;
}

void tipc_udp_media_stop(void)
{
	int err;

	err = kthread_stop(task_send);
	WARN_ON(err);
}
