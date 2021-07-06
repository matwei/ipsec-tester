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

#include "util.h"

#define MAX_SOCKET_BUF 10240

/**
 * A structure holding metadata about the received datagram
 * */
typedef struct {
	/// The socket type (usually SOCK_DGRAM)
	int so_type;
	/// A pointer to a string describing the socket type
	char *sock_type;
	/// The destination address of a received datagram (local address)
	char pladdr[INET6_ADDRSTRLEN];
	/// The local address in network byte order
	struct in6_addr laddr;

	/// This can point either to the whole 16 bytes of an IPv6
	/// address or to the last 4 bytes of an IPv4-mapped IPv6
	/// address.
	chunk_t laddress;
	/// The local port of a UDP datagram
	unsigned short lport;
	/// The local port of a UDP datagram in network byte order
	unsigned short lportn;
	/// The source address of a received datagram (remote address)
	char praddr[INET6_ADDRSTRLEN];
	/// The remote address in network byte order
	struct in6_addr raddr;

	/// This can point either to the whole 16 bytes of an IPv6
	/// address or to the last 4 bytes of an IPv4-mapped IPv6
	/// address.
	chunk_t raddress;
	/// The remote port of a UDP datagram
	unsigned short rport;
	/// The remote port of a UDP datagram in network byte order
	unsigned short rportn;
} datagram_spec;

/**
 * A structure holding auxillary data for a IKEv2 message
 */
typedef struct {
	/// The socket used to receive the message and send the answer
	int sockfd;
	/// The struct msghdr used by recvmsg() / sendmsg()
	struct msghdr msg;
	/// The struct sockaddr_in6 used by recvmsg() for the source address
	struct sockaddr_in6 paddr;
	/// The struct iovec required for recvmsg() / sendmsg()
	struct iovec iov[1];
	/// The cmsghdr and buffer for recvmsg() / sendmsg()
	union {
		struct cmsghdr cm;	// this is to control the alignment
		char control[1000];
	} control_un;
	/// The buffer for the received / sent data
	unsigned char buf[MAX_SOCKET_BUF];
	/// A pointer to the various parameters of the received datagram
	datagram_spec *ds;
} socket_msg;

typedef void (*socket_cb_handler)(int sockfd, void *cb_env);

datagram_spec *get_ds(datagram_spec * ds, socket_msg * sm);
int socket_listen(char const *dev, socket_cb_handler cb, void *env);
ssize_t socket_recvmsg(socket_msg * sm);
ssize_t socket_sendmsg(socket_msg * sm);

chunk_t socket_remote_address(socket_msg * sm);

#endif /* !IISOCKETS_H */
