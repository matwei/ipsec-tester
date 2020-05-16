/** \file ipsec.c
 * \brief IPsec related functions
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

#include "ipsec.h"

#include <string.h>

typedef struct __attribute__((__packed__)) {
	uint64_t ispi, rspi;
	uint8_t npl;
	unsigned int min_ver : 4, maj_ver : 4;
	uint8_t extype, flags;
	uint32_t mid, length;
} ike_header;

typedef struct __attribute__((__packed__)) {
	uint8_t npl;
	unsigned int reserved : 7;
	unsigned int critical : 1;
	uint16_t pl_length; 
} ike_gph;	// generic paylod header

#define MIN_IKE_DATAGRAM_LENGTH sizeof(ike_header)

#define EXCHANGE_IKE_SA_INIT 34
#define EXCHANGE_IKE_AUTH 35
#define EXCHANGE_CREATE_CHILD_SA 36
#define EXCHANGE_INFORMATIONAL 37

#define NPL_NONE 0
#define NPL_SA 33
#define NPL_D 42
#define NPL_V 43
#define NPL_SK 46

/**
 * Approve that the IKE header is valid
 *
 * @param buf points at the beginning of the IKE header in the
 *            datagramm.
 *
 *            This is not necessary the beginning of the UDP-Payload
 *            since a NAT-T IKE datagramm starts with a non-ESP marker
 *            that must be skipped when calling this function.
 *
 * @param buflen number of received octets after buf
 */
int approve_ike_header(unsigned char *buf,
		       ssize_t buflen) {
	ike_header *ih = (ike_header *)buf;
	uint32_t ih_length = ntohl(ih->length);
	zlog_category_t *zc = zlog_get_category("IKE");
	if (buflen < sizeof(ike_header)) {
		zlog_debug(zc,
			   "datagram length (%ld) < sizeof of IKE header",
			   buflen);
		return 0;
	}
	if (buflen != ih_length) {
		zlog_debug(zc,
			   "datagram length (%ld) doesn't match length in IKE header (%ld)",
			   buflen,
			   (long)ih_length);
		return 0;
	}
	if (2 != ih->maj_ver || 0 != ih->min_ver) {
		zlog_debug(zc,
			   "unknown IKE version: %d.%d",
			   ih->maj_ver,
			   ih->min_ver);
		return 0;
	}
	else {
		zlog_info(zc,
			   "IKE version: %d.%d",
			   ih->maj_ver,
			   ih->min_ver);
	}
	switch (ih->extype) {
		case EXCHANGE_IKE_SA_INIT:
		case EXCHANGE_IKE_AUTH:
		case EXCHANGE_CREATE_CHILD_SA:
		case EXCHANGE_INFORMATIONAL:
			zlog_debug(zc,
				   "exchange type: %hu",
				   ih->extype);
			break;
		default:
			zlog_debug(zc,
				   "unknown exchange type: %hu",
				   ih->extype);
			return 0;
	}
	switch (ih->npl) {
		case NPL_NONE:
			zlog_debug(zc,
				   "no next payload");
			break;
		case NPL_SA:
		case NPL_D:
		case NPL_V:
		case NPL_SK:
			zlog_debug(zc,
				   "next payload: %hu",
				   ih->npl);
			break;
		default:
			zlog_debug(zc,
				   "unknown next payload: %hu",
				   ih->npl);
			return 0;
	}
	zlog_info(zc,"IKE header OK");
	return 1;
}// approve_ike_header()

void ipsec_handle_datagram(int fd, ipsec_s * is) {
	socket_msg sm = { .sockfd=fd };
	ssize_t result;
	uint32_t spi = 0;

	char mdc_buf[5];
	unsigned int mdc_cnt = ++(is->mdc_counter);
	snprintf(mdc_buf,sizeof(mdc_buf),"%4.4x",mdc_cnt);
	zlog_put_mdc("dg", mdc_buf);

	if (0 >= (result = socket_recvmsg(&sm))) {
		return;
	}

	datagram_spec ds = {};
	get_ds(&ds, &sm);

	if (SOCK_DGRAM == ds.so_type) {
		if (500 == ds.lport) {
			zlog_category_t *zc = zlog_get_category("IKE");
			zlog_info(zc, "investigating IKE datagram");
			if (!approve_ike_header(sm.buf,
						result)) {
				zlog_info(zc, "IKE datagram not approved");
			}
		}
		else if (4500 == ds.lport) {
			if (memcmp(&spi,sm.buf,4)) {
				zlog_category_t *zc = zlog_get_category("ESP");
				zlog_info(zc, "investigating NAT-T ESP datagram");
			}
			else {
				zlog_category_t *zc = zlog_get_category("IKE");
				zlog_info(zc, "investigating NAT-T IKE datagram");
				if (!approve_ike_header(sm.buf+4,
							result-4)) {
					zlog_info(zc, "IKE datagram not approved");
				}
			}
		}
	}

	// for now send the datagramm back as echo
	sm.msg.msg_iov[0].iov_len= result;
	socket_sendmsg(&sm);
}// ipsec_handle_ike()
