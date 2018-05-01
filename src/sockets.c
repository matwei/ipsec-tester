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

ssize_t socket_recvfrom(int sockfd) {
	unsigned char buf[MAX_SOCKET_BUF];
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	char ipstr[INET6_ADDRSTRLEN];
	int result;

	if (0 > (result = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen))) {
		perror("socket_recvfrom");
	}
	else {
		printf("received %d bytes with buffer of %d bytes\n", result, MAX_SOCKET_BUF);
		printf(" from IP address %s\n",
		       inet_ntop(addr.ss_family,
			         AF_INET == addr.ss_family
				 ?  (void*)&(((struct sockaddr_in *)&addr)->sin_addr)
				 :  (void*)&(((struct sockaddr_in6 *)&addr)->sin6_addr),
			         ipstr, sizeof ipstr));
	}
	return result;
}// socket_revfrom()

/**
 * \brief Listen for datagrams for the IPsec interpreter
 *
 * \param dev name of network device for IPsec
 * \param ds data store handle
 * \param ih callback function for received datagrams
 * \return 0 on success, -1 on error condition
 */
int socket_listen(char const *dev, datastore_s ds, ipsec_handler ih) {
	int efd, ikefd4;
	struct epoll_event * events;

	ikefd4 = bind_socket(AF_INET,SOCK_DGRAM, PORT_IKE);

	efd = epoll_create1(0);
	if (-1 == efd) {
		perror("epoll_create");
		abort();
	}
	if (0 <= ikefd4) {
		add_fd(efd, ikefd4, EPOLLIN);
	}
	events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
	while (1) {
		int n = epoll_wait(efd, events, MAX_EVENTS, -1);
		for(int i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
			}
			else if (ikefd4 == events[i].data.fd) {
				if (events[i].events & EPOLLIN) {
					//ipsec_handle_ike(ikefd4);
					socket_recvfrom(ikefd4);
				}
			}
		}
	}
	close(ikefd4);
}// socket_listen()
