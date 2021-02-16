/** \file ipsec.h
 * \brief definitions regarding IPsec handling
 */
/*
 * Copyright (C) 2017 Mathias Weidner <mathias@mamawe.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef IPSEC_H
#define IPSEC_H

#include "sockets.h"
#include "util.h"

#include <sys/types.h>
#include <zlog.h>

typedef struct {
	int mdc_counter;
} ipsec_s;

/**
 * \brief Callback to handle IPsec datagrams
 *
 * \param fd the file descriptor of the receiving socket
 */
typedef void (*ipsec_dg_handler)(int fd, ipsec_s *is);

void ipsec_handle_datagram(int, ipsec_s *);

#define ITIP_ZLOG_CONF "zlog.conf"

buffer_const_err_s ike_find_last_payload(unsigned char const * buf, size_t buflen);
buffer_const_err_s ike_response_no_proposal_chosen(unsigned char * buf, size_t buflen);

/**
 * The structure holding one peer in the SAD
 */
typedef struct {
	/// the address of the peer
	char raddr[INET6_ADDRSTRLEN];
	/// the UDP port of the peer
	unsigned short rport;
	/// the SPI of the peer (either initiator or responder)
	uint64_t rspi;
	/// my address
	char laddr[INET6_ADDRSTRLEN];
	/// my UDP port
	unsigned short lport;
	/// my SPI (either initiator or responder)
	uint64_t lspi;
	/// am I the initiator
	int initiator;
	/// next message ID of initiator
	uint32_t mid_i;
	/// next message ID of responder
	uint32_t mid_r;
} sad_peer;

make_err_s(sad_peer *, sad_peer);

sad_peer_err_s sad_get_peer_record(ipsec_s *is, sad_peer * peer);
sad_peer_err_s sad_put_peer_record(ipsec_s *is, sad_peer * peer);

#endif /* !IPSEC_H */
