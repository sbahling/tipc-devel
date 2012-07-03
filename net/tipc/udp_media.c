/*
 * net/tipc/udp_media.c: IP/UDP bearer support for TIPC
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

#define DEFAULT_UDP_PORT 6834
#define DEFAULT_MC_GROUP "228.0.0.1"
#define MAX_UDP_BEARERES 1
#define UDP_STR_MAX 64
#define UDP_ADDR_OFFSET	4

/**
 *
 */
struct udp_bearer {
	struct tipc_bearer *bearer;
	struct socket *socket;
	struct task_struct *task_recv;
	struct task_struct *task_send;
};


static struct tipc_media udp_media_info;
static struct udp_bearer udp_bearers[MAX_UDP_BEARERS];
static int udp_started;

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
	a->media_id = TIPC_MEDIA_TYPE_UDP;
	//a should now contain:
	//AF_INET/udpport/ipv4addr
	memcpy(a->value, sin, sizeof(struct sockaddr_in));
	a->broadcast = ((sin->sin_addr & 0xE0) == 0xE0)
		
}

static int send_msg(struct sk_buff *skb, struct tipc_bearer *tb_ptr,
		    struct tipc_media_addr *dest)
{
	return -EINVAL;
}

static int tipc_udp_recv(void *data)
{
}

static int tipc_udp_recv(void *data)
{
	while(1)
	{
	//	wait_event_interruptible();
	}
}

static int enable_bearer(struct tipc_bearer *tb_ptr)
{
	struct udp_bearer *ub_ptr = &udp_bearers[0];
	struct ip_mreq mreq;
	struct sockaddr_in sin;
	int err;
	char *mcaddr = strchr((const char *) tb_ptr->name, ':') + 1;
	char *port = strchr(mcaddr, ':') + 1;
	char *listenaddr = strchr(port, ':') + 1;
	
//UDP bearer string:
//(-be=)udp:227.0.0.4:6666:192.168.0.1
//      <media>:<multicastaddr>:<udpport>:<listenaddr>
	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0, &ub_ptr->socket);
	BUG_ON(err);
	inet_pton(AF_INET, DEFAULT_MC_GROUP, &mreq.imr_multiaddr.s_addr);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	err = kernel_setsockopt(ub_ptr->socket, IPPROTO_IP,
				IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	BUG_ON(err);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(DEFAULT_UDP_PORT);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	//TODO: stringify macro on fn name
	ub_ptr->task_send = kthread_run(tipc_udp_recv, NULL, "tipc_udp_recv");
	ub_ptr->task_recv = kthread_run(tipc_udp_send, NULL, "tipc_udp_send");
	


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
	if (inet_ntop(sin->sin_family, sin->sin_addr, tmp, 255) == NULL) {
		pr_err("inet_ntop failed\n");
		return 1; //TODO: -EINVAL??
	}
	snprintf(buf, size, "%s port:%u",tmp, sin->sin_port);
	return 0;
}

static int udp_msg2addr(struct tipc_media_addr *a, char *msg_area)
{
	if (msg_area[TIPC_MEDIA_TYPE_OFFSET] != TIPC_MEDIA_TYPE_UDP)
		return 1; //TODO: -EINVAL?
	udp_media_addr_set(a, msg_area + UDP_ADDR_OFFSET);
	return 0;
}

