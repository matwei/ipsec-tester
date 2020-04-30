/** \file iisockets.c
 * \brief handle sockets for IPsec interpreter
 */
/*
 Copyright (C) 2018 Mathias Weidner <mathias@mamawe.net>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* need _GNU_SOURCE to get in6_pktinfo from netinet/in.h on linux */
#define _GNU_SOURCE

#include "ipsec.h"
#include "sockets.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_EVENTS 64
#define PORT_IKE "500"
#define PORT_IPSEC_NAT "4500"

char * socket_type(int sockfd);

void add_fd(int efd, int fd, uint32_t events) {
	struct epoll_event event = { .data.fd=fd, .events=events};
	int s = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
	if (-1 == s) {
		perror("epoll_ctl");
		abort();
	}
}// add_fd()

int bind_socket(int family, int st, const char *port) {
	int rv, sockfd;
	struct addrinfo *p, *servinfo;
	struct addrinfo hints;
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = family;
	hints.ai_socktype = st;
	hints.ai_flags = AI_PASSIVE;

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		abort();
	}
	for (p = servinfo; NULL != p; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				     p->ai_protocol)) == -1) {
			perror("bind_socket: socket");
			continue;
	        }
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("bind_socket: bind");
			continue;
		}
	}
	freeaddrinfo(servinfo);
	return sockfd;
}// bind_socket()

datagram_spec * get_ds(datagram_spec *ds, socket_msg * sm) {
	struct cmsghdr *cmptr;
	socklen_t length = sizeof(ds->so_type);
	struct sockaddr_in6 *raddr = (struct sockaddr_in6 *)sm->msg.msg_name;
	struct sockaddr_in6 laddr = {};
	socklen_t laddrlen = sizeof(laddr);

	if (getsockopt(sm->sockfd, SOL_SOCKET, SO_TYPE, &(ds->so_type), &length)) {
		perror("socket_type");
	}
	switch (ds->so_type) {
		case SOCK_STREAM: ds->sock_type =  "TCP"; break;
		case SOCK_DGRAM:  ds->sock_type =  "UDP"; break;
		case SOCK_RAW:    ds->sock_type =  "RAW"; break;
		default:          ds->sock_type =  "UNKOWN";
	}
	for (cmptr = CMSG_FIRSTHDR(&sm->msg); cmptr != NULL;
	     cmptr = CMSG_NXTHDR(&sm->msg, cmptr)) {
		if (cmptr->cmsg_level == IPPROTO_IPV6 &&
		    cmptr->cmsg_type  == IPV6_PKTINFO) {
			struct in6_pktinfo *pkt = (struct in6_pktinfo*)CMSG_DATA(cmptr);
			struct in6_addr *dap = &(pkt->ipi6_addr);
			inet_ntop(AF_INET6,
				  (void*)dap,
				  ds->laddr, sizeof(ds->laddr));
		}
	}
	if (0 > getsockname(sm->sockfd, &laddr, &laddrlen)) {
		perror("getsockname");
	}
	ds->lport = ntohs(laddr.sin6_port);
	inet_ntop(AF_INET6,
	          (void*)&(raddr->sin6_addr),
	          ds->raddr, sizeof(ds->raddr));
	ds->rport = ntohs(raddr->sin6_port);
	return ds;
} // get_ds()

ssize_t socket_recvmsg(socket_msg *smp) {
	struct sockaddr_in6 saddr = {};
	struct iovec iov[1];
	int result;
	union {
		struct cmsghdr cm; // this is to control the alignment
		char   control[1000];
	} control_un;
	int opt = 1;

	smp->msg.msg_control = control_un.control;
	smp->msg.msg_controllen = sizeof(control_un.control);
	smp->msg.msg_flags   = 0;
	smp->msg.msg_name    = &saddr;
	smp->msg.msg_namelen = sizeof(saddr);
	iov[0].iov_base = smp->buf;
	iov[0].iov_len  = sizeof(smp->buf);
	smp->msg.msg_iov     = iov;
	smp->msg.msg_iovlen  = 1;

	result = setsockopt(smp->sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
	if (result) {
		perror("setsockopt");
	}
	if (0 > (result = recvmsg(smp->sockfd, &(smp->msg), 0))) {
		perror("socket_recvmsg");
	}
	else {
		datagram_spec ds ={};
		get_ds(&ds,smp);
		zlog_category_t *zc = zlog_get_category("NET");
		zlog_info(zc, "rcvd %d bytes %s [%s]:%hu to [%s]:%hu",
			  result,
			  ds.sock_type,
			  ds.raddr,
			  ds.rport,
			  ds.laddr,
			  ds.lport);
	}
	return result;
}// socket_recvmsg()

ssize_t socket_sendmsg(socket_msg *sm) {
	datagram_spec ds ={};
	zlog_category_t *zc;

	ssize_t result = sendmsg(sm->sockfd, &(sm->msg), MSG_DONTWAIT);
	get_ds(&ds, sm);
	zc = zlog_get_category("NET");
	zlog_info(zc, "sent %zu bytes %s [%s]:%hu to [%s]:%hu",
		  result,
		  ds.sock_type,
		  ds.laddr,
		  ds.lport,
		  ds.raddr,
		  ds.rport);
	return result;
}// socket_sendmsg()

/**
 * \brief Listen for datagrams for the IPsec interpreter
 *
 * \param dev name of network device for IPsec
 * \param ds data store handle
 * \param ih callback function for received datagrams
 * \return 0 on success, -1 on error condition
 */
int socket_listen(char const *dev, socket_cb_handler cb, void * cb_env) {
	int efd, ikefd, ipsecnatfd;
	struct epoll_event * events;

	ikefd = bind_socket(AF_INET6,SOCK_DGRAM, PORT_IKE);
	ipsecnatfd = bind_socket(AF_INET6,SOCK_DGRAM, PORT_IPSEC_NAT);

	efd = epoll_create1(0);
	if (-1 == efd) {
		perror("epoll_create");
		abort();
	}
	if (0 <= ikefd) {
		add_fd(efd, ikefd, EPOLLIN);
	}
	if (0 <= ipsecnatfd) {
		add_fd(efd, ipsecnatfd, EPOLLIN);
	}
	events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
	while (1) {
		int n = epoll_wait(efd, events, MAX_EVENTS, -1);
		for(int i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
			}
			else if (ikefd == events[i].data.fd) {
				if (events[i].events & EPOLLIN) {
					cb(ikefd, cb_env);
				}
			}
			else if (ipsecnatfd == events[i].data.fd) {
				if (events[i].events & EPOLLIN) {
					cb(ipsecnatfd, cb_env);
				}
			}
		}
	}
	close(ikefd);
}// socket_listen()

char * socket_type(int sockfd) {
	int type;
	socklen_t length = sizeof(type);

	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &length)) {
		perror("socket_type");
		return NULL;
	}
	switch (type) {
		case SOCK_STREAM: return "TCP";
		case SOCK_DGRAM:  return "UDP";
		case SOCK_RAW:    return "RAW";
		default:          return "UNKOWN";
	}
}// socket_type()

