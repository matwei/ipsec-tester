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

#define IKEv2_SPID_IKE 1
#define IKEv2_SPID_AH  2
#define IKEv2_SPID_ESP 3

/** maximal size of KE data (8192 bit) */
#define MAX_KE_DATA	1024

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

/** internal transform struct
 */
typedef struct {
	uint8_t type;
	uint16_t id;
	char * name;
	union {
		short keylen;
	} attr;
} ikev2_transform;

typedef struct {
	ikev2_transform * encr;
	ikev2_transform * prf;
	ikev2_transform * integ;
	ikev2_transform * dh;
	ikev2_transform * esn;
} ikev2_transform_set;

/**
 * The structure holding one peer in the SAD
 */
typedef struct {
	/// the SPI of this SA entry
	uint64_t spi;
	/// the security protocol ID: 1 IKE, 2 AH, 3 ESP
	uint8_t spid;
	/// the destination address
	struct in6_addr daddr;
	char pdaddr[INET6_ADDRSTRLEN];
	/// the source address
	struct in6_addr saddr;
	char psaddr[INET6_ADDRSTRLEN];
	ikev2_transform_set transform;
	unsigned int state;
	union {
		uint8_t ke[MAX_KE_DATA];
	} key;
} ipsec_sa;

make_err_s(ipsec_sa *, ipsec_sa);

ipsec_sa_err_s sad_add_reverse_record(ipsec_sa * peer, uint64_t spi);
ipsec_sa_err_s sad_get_record(ipsec_sa * peer);
ipsec_sa_err_s sad_put_record(ipsec_sa * peer);
void sad_dump_records(void (*pr)(const char *));

buffer_const_err_s ike_find_last_payload(unsigned char const * buf, size_t buflen);
buffer_const_err_s ike_response_ike_sa_init(unsigned char * buf, size_t buflen, ipsec_sa * peer);
buffer_const_err_s ike_response_no_proposal_chosen(unsigned char * buf, size_t buflen);

#endif /* !IPSEC_H */
