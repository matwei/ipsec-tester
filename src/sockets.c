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

#include "datastore.h"
#include "ipsec.h"
#include "sockets.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EVENTS 64
#define MAX_SOCKET_BUF 20480
#define PORT_IKE "500"
#define PORT_IPSEC_NAT "4500"

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

ssize_t socket_recvmsg(int sockfd) {
	unsigned char buf[MAX_SOCKET_BUF];
	char ipstr1[INET6_ADDRSTRLEN], ipstr2[INET6_ADDRSTRLEN];
	struct sockaddr_storage saddr = {},daddr = {};
	struct msghdr msg;
	struct iovec iov[1];
	socklen_t addrlen = sizeof(saddr);
	int flags, result;
	zlog_category_t *zc;
	struct cmsghdr *cmptr;
	union {
		struct cmsghdr cm; // this is to control the alignment
		char   control[1000];
	} control_un;
	int opt = 1;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);
	msg.msg_flags   = 0;
	msg.msg_name    = &saddr;
	msg.msg_namelen = sizeof(saddr);
	iov[0].iov_base = buf;
	iov[0].iov_len  = sizeof(buf);
	msg.msg_iov     = iov;
	msg.msg_iovlen  = 1;
	flags           = 0;
	zc = zlog_get_category("NET");
	result = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt));
	if (result) {
		perror("setsockopt");
	}
	if (0 > (result = recvmsg(sockfd, &msg, 0))) {
		perror("socket_recvmsg");
	}
	else {
		for (cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL;
		     cmptr = CMSG_NXTHDR(&msg, cmptr)) {
			if (cmptr->cmsg_level == IPPROTO_IPV6 &&
			    cmptr->cmsg_type  == IPV6_PKTINFO) {
				struct in6_pktinfo *pkt = CMSG_DATA(cmptr);
				struct in6_addr *dap = &(pkt->ipi6_addr);
				memcpy(&daddr,dap,sizeof(daddr));
			}
		}
		zlog_info(zc, "received %d bytes from IP address %s to %s",
			  result,
		          inet_ntop(saddr.ss_family,
			            AF_INET == saddr.ss_family
				    ?  (void*)&(((struct sockaddr_in *)&saddr)->sin_addr)
				    :  (void*)&(((struct sockaddr_in6 *)&saddr)->sin6_addr),
			            ipstr1, sizeof ipstr1),
		          inet_ntop(AF_INET6,
			            (void*)&daddr,
			            ipstr2, sizeof ipstr2));
	}
	return result;
}// socket_recvmsg()

/**
 * \brief Listen for datagrams for the IPsec interpreter
 *
 * \param dev name of network device for IPsec
 * \param ds data store handle
 * \param ih callback function for received datagrams
 * \return 0 on success, -1 on error condition
 */
int socket_listen(char const *dev, datastore_s ds, ipsec_handler ih) {
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
					//ipsec_handle_ike(ikefd);
					socket_recvmsg(ikefd);
				}
			}
			else if (ipsecnatfd == events[i].data.fd) {
				if (events[i].events & EPOLLIN) {
					//ipsec_handle_ike(ipsecnatfd);
					socket_recvmsg(ipsecnatfd);
				}
			}
		}
	}
	close(ikefd);
}// socket_listen()
