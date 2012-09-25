/*
 * net/tipc/diag.c: TIPC socket diag
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

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/sock_diag.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include "core.h"
#include "port.h"
#include "tipc_diag.h"

static int sk_diag_fill(struct sock *sk, struct sk_buff *skb,
			struct tipc_diag_req *req,
			u32 portid, u32 seq, u32 flags, int sk_ino)
{
	struct tipc_port *p_ptr;
	struct nlmsghdr *nlh;
	struct tipc_diag_msg *rep;

	p_ptr = tipc_sk_port(sk);
	nlh = nlmsg_put(skb, portid, seq, SOCK_DIAG_BY_FAMILY, sizeof(*rep),
			flags);
	if (!nlh)
		return -EMSGSIZE;

	rep = nlmsg_data(nlh);
	rep->tdiag_family = AF_TIPC;
	rep->tdiag_type = sk->sk_type;
	rep->tdiag_state = sk->sk_socket->state;
	rep->tdiag_ino = sk_ino;
	rep->tdiag_uid = from_kuid_munged(sk_user_ns(sk), sock_i_uid(sk));
	rep->tdiag_rqueue = sk->sk_receive_queue.qlen;
	rep->tdiag_wqueue = (p_ptr->sent - p_ptr->acked);
	rep->tdiag_cong = (__u8) p_ptr->congested;
	rep->tdiag_probe = (__u8) p_ptr->probing_state;
	rep->tdiag_local.ref = p_ptr->ref;
	rep->tdiag_local.node = tipc_own_addr;
	if (p_ptr->connected) {
		rep->tdiag_remote.ref = msg_destport(&p_ptr->phdr);
		rep->tdiag_remote.node = msg_destnode(&p_ptr->phdr);
		if (p_ptr->conn_type != 0) {
			rep->tdiag_name.type = p_ptr->conn_type;
			rep->tdiag_name.instance = p_ptr->conn_instance;
		}
	}
	sock_diag_save_cookie(sk, rep->tdiag_cookie);
	return nlmsg_end(skb, nlh);
}


int sk_diag_dump(struct sock *sk, struct sk_buff *skb,
			struct tipc_diag_req *req,
			u32 portid, u32 seq, u32 flags)
{
	int sk_ino;

	sk_ino = sock_i_ino(sk);
	if (!sk_ino)
		return 0;
	return sk_diag_fill(sk, skb, req, portid, seq, flags, sk_ino);
}


static int tipc_diag_handler_dump(struct sk_buff *skb, struct nlmsghdr *h)
{
	int hdrlen = sizeof(struct tipc_diag_req);
	struct net *net = sock_net(skb->sk);
	int err = -EINVAL;

	if (nlmsg_len(h) < hdrlen)
		return err;
	if (h->nlmsg_flags & NLM_F_DUMP) {
		struct netlink_dump_control c = {
			.dump = tipc_diag_dump,
		};
		err = netlink_dump_start(net->diag_nlsk, skb, h, &c);
	}
	return err;
}

static const struct sock_diag_handler tipc_diag_handler = {
	.family = AF_TIPC,
	.dump = tipc_diag_handler_dump,
};

int tipc_diag_init(void)
{
	return sock_diag_register(&tipc_diag_handler);
}
void tipc_diag_exit(void)
{
	sock_diag_unregister(&tipc_diag_handler);
}

MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_NETLINK, NETLINK_SOCK_DIAG, 30 /* AF_TIPC */);
