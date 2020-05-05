/*
 * iisockets.h
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

#ifndef IISOCKETS_H
#define IISOCKETS_H

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_SOCKET_BUF 10240

typedef struct {
	int sockfd;
	struct msghdr msg;
	struct sockaddr_in6 paddr;
	struct iovec iov[1];
	union {
		struct cmsghdr cm; // this is to control the alignment
		char   control[1000];
	} control_un;
	unsigned char buf[MAX_SOCKET_BUF];
} socket_msg;

typedef struct {
	int so_type;
	char * sock_type;
	char laddr[INET6_ADDRSTRLEN];
	unsigned short lport;
	char raddr[INET6_ADDRSTRLEN];
	unsigned short rport;
} datagram_spec;

typedef void (*socket_cb_handler)(int sockfd, void * cb_env);

datagram_spec * get_ds(datagram_spec *ds, socket_msg * sm);
int socket_listen(char const *dev, socket_cb_handler cb, void *env);
ssize_t socket_recvmsg(socket_msg *sm);
ssize_t socket_sendmsg(socket_msg *sm);

#endif /* !IISOCKETS_H */
