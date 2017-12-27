/** \file pcapture.h
 * \brief definitions for the packet capture
 */
/*
 * pcapture.h
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

#ifndef PCAPTURE_H
#define PCAPTURE_H

#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>

#include "datastore.h"
#include "ipsec.h"

#define ETHER_ADDR_LEN 6

/**
 * \brief user data that is handed down from pcap_loop() to callback
 *        function
 */
typedef struct {
	datastore_s *ds;
	pcap_t *handle;
} pcapture_user_data;

/**
 * \brief ethernet header in captured datagram
 */
typedef struct {
	uint8_t  ether_dst[ETHER_ADDR_LEN];
	uint8_t  ether_src[ETHER_ADDR_LEN];
	uint16_t ether_type;
} sniff_ethernet;

/**
 * \brief IPv4 header in captured datagram
 */
typedef struct {
	uint8_t  ihl : 4,
		 version : 4;
	uint8_t  tos;
	uint16_t len;
	uint16_t id;
	uint16_t offset;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t sum;
	struct in_addr src;
	struct in_addr dst;
} sniff_ip4;

#define IP4_RF 0x8000		/* reserved fragment flag */
#define IP4_DF 0x4000		/* dont fragment flag */
#define IP4_MF 0x2000		/* more fragments flag */
#define IP4_OFFMASK 0x1fff	/* mask for fragmenting bits */

/**
 * \brief IPv6 header in captured datagram
 */
typedef struct {
	uint32_t vcf;
	uint16_t length;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct   in6_addr src;
	struct   in6_addr dst;
} sniff_ip6;

#define IP6_VER(ip6) (htonl((ip6)->vcf) >> 28)
#define IP6_TC(ip6)  ((htonl((ip6)->vcf) >> 20) & 0xff)
#define IP6_FL(ip6)  (htonl((ip6)->vcf) & 0xfffff)

int pcapture(char const *, datastore_s, ipsec_handler);

int pcapture_create_file(char const *, char const *);

#endif /* !PCAPTURE_H */
