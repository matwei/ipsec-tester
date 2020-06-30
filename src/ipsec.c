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

#include <stdbool.h>
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

typedef struct __attribute__((__packed__)) {
	uint8_t last_substruct;
	uint8_t reserved;
	uint16_t proposal_length;
	uint8_t proposal_num;
	uint8_t protocol_id;
	uint8_t spi_size;
	uint8_t num_transforms;
} ike_sa_proposal;

typedef struct __attribute__((__packed__)) {
	uint8_t last_substruct;
	uint8_t reserved1;
	uint16_t transform_length;
	uint8_t transform_type;
	uint8_t reserved2;
	uint16_t transform_id;
} ike_sa_transform;

typedef struct __attribute__((__packed__)) {
	uint16_t format_type;
	uint16_t length_value;
} ike_sa_tf_attribute;

#define MIN_IKE_DATAGRAM_LENGTH sizeof(ike_header)

#define EXCHANGE_IKE_SA_INIT 34
#define EXCHANGE_IKE_AUTH 35
#define EXCHANGE_CREATE_CHILD_SA 36
#define EXCHANGE_INFORMATIONAL 37

#define PROTOCOL_ID_IKE 1
#define PROTOCOL_ID_AH 2
#define PROTOCOL_ID_ESP 3

#define TRANSFORM_ENCR 1
#define TRANSFORM_PRF 2
#define TRANSFORM_INTEG 3
#define TRANSFORM_DH 4
#define TRANSFORM_ESN 5

#define NPL_NONE 0
#define NPL_SA 33
#define NPL_N 41
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
int ike_approve_header(unsigned char *buf,
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
		case NPL_N:
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
}// ike_approve_header()

/**
 * Return char array containing name of protocol ID in proposal.
 *
 * @param protocol_id protocol ID in proposal from SA payload
 */
const char * ike_protocol_id_name(uint8_t protocol_id) {
	switch (protocol_id) {
		case PROTOCOL_ID_IKE:
			return "IKE";
		case PROTOCOL_ID_AH:
			return "AH";
		case PROTOCOL_ID_ESP:
			return "ESP";
		default:
			return "unknown protocol ID";
	}
}// ike_protocol_id_name()

/**
 * Return char array containing name of transform type in proposal.
 *
 * @param type - transform type from proposal
 */
const char * ike_transform_type_name(uint8_t type) {
	switch (type) {
		case TRANSFORM_ENCR:
			return "ENCR";
		case TRANSFORM_PRF:
			return "PRF";
		case TRANSFORM_INTEG:
			return "INTEG";
		case TRANSFORM_DH:
			return "DH";
		case TRANSFORM_ESN:
			return "ESN";
		default:
			return "unknown transform type";
	}
}// ike_transform_type_name()

/**
 * Return char array containing name of ENCR transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char * ike_transform_encr_name(uint16_t id) {
	switch (id) {
		case 1:
			return "DES_IV64";
		case 2:
			return "DES";
		case 3:
			return "3DES";
		case 4:
			return "RC5";
		case 5:
			return "IDEA";
		case 6:
			return "CAST";
		case 7:
			return "BLOWFISH";
		case 8:
			return "3IDEA";
		case 9:
			return "DES_IV32";
		case 11:
			return "NULL";
		case 12:
			return "AES_CBC";
		case 13:
			return "AES_CTR";
		default:
			return "unknown ENCR";
	}
}// ike_transform_encr_name()

/**
 * Return char array containing name of PFR transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char * ike_transform_prf_name(uint16_t id) {
	switch (id) {
		case 1:
			return "HMAC_MD5";
		case 2:
			return "HMAC_SHA1";
		case 3:
			return "HMAC_TIGER";
		case 4:
			return "AES128_XCBC";
		case 5:
			return "HMAC_SHA2_256";
		case 6:
			return "HMAC_SHA2_384";
		case 7:
			return "HMAC_SHA2_512";
		case 8:
			return "AES128_CMAC";
		case 9:
			return "HMAC_STRIBOG_512";
		default:
			return "unknown PRF";
	}
}// ike_transform_prf_name()


/**
 * Return char array containing name of INTEG transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char * ike_transform_integ_name(uint16_t id) {
	switch (id) {
		case 1:
			return "HMAC_MD5_96";
		case 2:
			return "HMAC_SHA1_96";
		case 3:
			return "DES_MAC";
		case 4:
			return "KPDK_MD5";
		case 5:
			return "AES_XCBC_96";
		case 6:
			return "HMAC_MD5_128";
		case 7:
			return "HMAC_SHA1_160";
		case 8:
			return "AES_CMAC_96";
		case 9:
			return "AES_128_GMAC";
		case 10:
			return "AES_192_GMAC";
		case 11:
			return "AES_256_GMAC";
		case 12:
			return "HMAC_SHA2_256_128";
		case 13:
			return "HMAC_SHA2_384_192";
		case 14:
			return "HMAC_SHA2_512_256";
		default:
			return "unknown INTEG";
	}
}// ike_transform_integ_name()


/**
 * Return char array containing name of DH transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char * ike_transform_dh_name(uint16_t id) {
	switch (id) {
		case 0:
			return "none";
		case 1:
			return "768-bit MODP Group";
		case 2:
			return "1024-bit MODP Group";
		case 5:
			return "1536-bit MODP Group";
		case 14:
			return "2048-bit MODP Group";
		case 15:
			return "3072-bit MODP Group";
		case 16:
			return "4096-bit MODP Group";
		case 17:
			return "6144-bit MODP Group";
		case 18:
			return "8192-bit MODP Group";
		case 19:
			return "256-bit random ECP Group";
		case 20:
			return "384-bit random ECP Group";
		case 21:
			return "521-bit random ECP Group";
		case 22:
			return "1024-bit MODP Group with 160-bit Prime Order Subgroup";
		case 23:
			return "2048-bit MODP Group with 224-bit Prime Order Subgroup";
		case 24:
			return "2048-bit MODP Group with 256-bit Prime Order Subgroup";
		case 25:
			return "192-bit random ECP Group";
		case 26:
			return "224-bit random ECP Group";
		case 27:
			return "brainpoolP224r1";
		case 28:
			return "brainpoolP256r1";
		case 29:
			return "brainpoolP384r1";
		case 30:
			return "brainpoolP512r1";
		case 31:
			return "Curve25519";
		case 32:
			return "Curve448";
		case 33:
			return "GOST3410_2012_256";
		case 34:
			return "GOST3410_2012_512";
		default:
			return "unknown DH group";
	}
}// ike_transform_dh_name()

/**
 * Return char array containing name of ESN ID in transform in proposal.
 *
 * @param id - ID from transform
 */
const char * ike_transform_esn_name(uint16_t id) {
	switch (id) {
		case 0:
			return "no ESN";
		case 1:
			return "ESN";
		default:
			return "unknown ESN";
	}
}// ike_transform_esn_name()

/**
 * Return char array containing name of protocol ID in proposal.
 *
 * @param transform_type - type of transform (ENCR, PRF, INTEG, DH, ESN)
 *
 * @param id - transform ID
 */
const char * ike_transform_id_name(uint8_t transform_type, uint16_t id) {
	switch (transform_type) {
		case TRANSFORM_ENCR:
			return ike_transform_encr_name(id);
		case TRANSFORM_PRF:
			return ike_transform_prf_name(id);
		case TRANSFORM_INTEG:
			return ike_transform_integ_name(id);
		case TRANSFORM_DH:
			return ike_transform_dh_name(id);
		case TRANSFORM_ESN:
			return ike_transform_esn_name(id);
		default:
			return "unknown transform type";
	}
}// ike_transform_id_name()

/**
 * parse transforms in proposals in SA payload
 *
 * @param buf - buffer containing transforms
 *
 * @param buflen - length of buffer
 *
 * @num_transforms - number of expected transforms
 */
int ike_parse_transforms(unsigned char *buf,
                         ssize_t buflen,
		         int num_transforms) {
	unsigned char *bp = buf;
	const unsigned char *ep = buf+buflen;
	zlog_category_t *zc = zlog_get_category("IKE");
	int transform_number = 1;
	while (transform_number <= num_transforms) {
		if (ep < bp + sizeof(ike_sa_transform)) {
			zlog_error(zc, "buffer to short for transform %u",
			           transform_number);
			return 0;
		}
		ike_sa_transform *tf = (ike_sa_transform *)bp;
		uint16_t tf_length = ntohs(tf->transform_length);
		uint16_t tf_id = ntohs(tf->transform_id);
		zlog_info(zc,
		          "  transform #%u [%hhu]: %s (%hhu): %s (%hu)",
			  transform_number,
			  tf_length,
			  ike_transform_type_name(tf->transform_type),
			  tf->transform_type,
			  ike_transform_id_name(tf->transform_type, tf_id),
			  tf_id);
		if (TRANSFORM_ENCR == tf->transform_type
			&& sizeof(ike_sa_transform) < tf_length) {
			ike_sa_tf_attribute *ap = (ike_sa_tf_attribute *)(bp + sizeof(ike_sa_transform));
			uint16_t attr_type = ntohs(ap->format_type);
			if ((attr_type & 0x8000)
				&& 14 == (attr_type &0x7fff)) {
				zlog_info(zc,
					  "   keylength: %hu",
					  ntohs(ap->length_value));
			}
		}
		bp += tf_length;
		++transform_number;
	}
	return 1;
}// ike_parse_transforms()

int ike_parse_sa_payload(unsigned char *buf,
                          ssize_t buflen) {
	unsigned char *bp = buf;
	const unsigned char *ep = buf+buflen;
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc,
	          "SA payload [%lu]",
		  buflen);
	while (ep > bp + sizeof(ike_sa_proposal)) {
		ike_sa_proposal *prop = (ike_sa_proposal *)bp;
		uint16_t prop_length = ntohs(prop->proposal_length);
		zlog_info(zc,
			  " proposal #%hhu [%hhu]: protocol: %s (%hhu), SPI size %hhu, %hhu transforms",
			  prop->proposal_num,
			  prop_length,
			  ike_protocol_id_name(prop->protocol_id),
			  prop->protocol_id,
			  prop->spi_size,
			  prop->num_transforms);
		if (!ike_parse_transforms(bp + sizeof(ike_sa_proposal),
			                  prop_length - sizeof(ike_sa_proposal),
					  prop->num_transforms)) {
			zlog_error(zc, "problem parsing proposal %hhu", prop->proposal_num);
			return 0;
		}
		if (ep == bp + prop_length) {
			if (0 == prop->last_substruct) {
				return 1;
			}
			else {
				zlog_info(zc,"last substruct not set at end of SA payload");
				return 0;
			}
		}
		if (0 == prop->last_substruct) {
			zlog_info(zc,"last substruct set but not end of SA payload");
			return 0;
		}
		bp += prop_length;
	}
	zlog_info(zc,
		  "proposal exceeds SA payload by %ld bytes",
		  bp-ep);
	return 0;
}// ike_parse_sa_payload()

/**
 * Return char array containing name of exchange type.
 *
 * @param extype binary IKE exchange type
 */
const char * ike_exchange_name(uint8_t extype) {
	switch (extype) {
		case EXCHANGE_IKE_SA_INIT:
			return "IKE_SA_INIT";
		case EXCHANGE_IKE_AUTH:
			return "IKE_AUTH";
		case EXCHANGE_CREATE_CHILD_SA:
			return "CREATE_CHILD_SA";
		case EXCHANGE_INFORMATIONAL:
			return "INFORMATIONAL";
		default:
			return "UNKNOWN";
	}
}// ike_exchange_name()

/**
 * Handle an IKE_SA_INIT exchange.
 *
 * @param fd the socket handle used to read the incoming datagram and
 *           send the answer.
 *
 * @param is information about IPsec states.
 *
 * @param buf points at the beginning of the IKE header in the
 *            datagramm.
 *            This is not necessary the beginning of the UDP-Payload
 *            since a NAT-T IKE datagramm starts with a non-ESP marker
 *            that must be skipped when calling this function.
 *
 * @param buflen number of received octets after buf.
 */
void ike_hm_ike_sa_init(int fd, ipsec_s *is,
                        unsigned char * buf, ssize_t buflen) {
	ike_header *ih = (ike_header *)buf;
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "handling IKE_SA_INIT");
	uint8_t npl = ih->npl;
	unsigned char * const ep = buf + buflen;
	unsigned char *bp = buf + sizeof(ike_header);
	while (bp < ep) {
		ike_gph * ngph = (ike_gph*)bp;
		uint16_t pl_length = ntohs(ngph->pl_length);
		if (bp + pl_length > ep) {
			zlog_error(zc,
			          "length of payload %hhu exceeds buffer",
				  npl);
			return;
		}
		zlog_debug(zc,
			  "payload %hhu, length: %hu",
			  npl, pl_length);
		switch (npl) {
			case 33: // Security Association (SA)
				if (ike_parse_sa_payload(bp+sizeof(ike_gph),
					                 pl_length-sizeof(ike_gph))) {
					// TODO: use SA payload
				}
				break;
				// TODO: parse other payloads
			default:
				zlog_info(zc,
					  "don't know how to handle payload %hhu",
					  npl);
		}
		npl = ngph->npl;
		bp += pl_length;
		if (NPL_NONE == npl && bp < ep) {
			zlog_info(zc,
			          "no next payload but %td bytes buffer left",
				  ep - bp);
			return;
		}
		else if (NPL_NONE != npl && bp >= ep) {
			zlog_error(zc,
			          "next payload %hhu but no bytes in buffer",
				  npl);
			return;
		}
	}
}// ike_hm_ike_sa_init()

/**
 * Handle an already approved IKE message
 *
 * @param fd the socket handle used to read the incoming datagram and
 *           send the answer.
 *
 * @param is information about IPsec states.
 *
 * @param buf points at the beginning of the IKE header in the
 *            datagramm.
 *            This is not necessary the beginning of the UDP-Payload
 *            since a NAT-T IKE datagramm starts with a non-ESP marker
 *            that must be skipped when calling this function.
 *
 * @param buflen number of received octets after buf.
 */
void ike_handle_message(int fd, ipsec_s *is,
                        unsigned char * buf, ssize_t buflen) {
	ike_header *ih = (ike_header *)buf;
	uint32_t ih_length = ntohl(ih->length);
	zlog_category_t *zc = zlog_get_category("IKE");

	switch (ih->extype) {
		case EXCHANGE_IKE_SA_INIT:
			ike_hm_ike_sa_init(fd, is, buf, buflen);
			break;
		case EXCHANGE_IKE_AUTH:
		case EXCHANGE_CREATE_CHILD_SA:
		case EXCHANGE_INFORMATIONAL:
		default:
			zlog_info(zc,
				   "can't handle %s message yet",
				   ike_exchange_name(ih->extype));
	}
}// ike_handle_message()

/**
 * Adjust the IKE header and send the datagram
 *
 * @param psm pointer to socket_msg used to send the datagram
 *
 * @param is_nat_t the datagram uses NAT-T
 *
 * @param length the length of the IKE payload excluding the IKE header
 */
ssize_t ike_send_datagram(socket_msg *psm,
			  bool is_nat_t,
			  ssize_t length) {
	ike_header *ih;
	ssize_t dglen = sizeof(ike_header) + length;

	if (is_nat_t) {
		dglen += 4;
		ih = (ike_header *)(psm->buf+4);
	}
	else {
		ih = (ike_header *)(psm->buf);
	}
	ih->length = htonl(sizeof(ike_header) + length);
	if (0 == length) {
		ih->npl = 0;
	}
	psm->msg.msg_iov[0].iov_len= dglen;
	return socket_sendmsg(psm);
}// ike_send_datagram()

/**
 * Handle the IPsec datagram
 *
 * @param fd the socket handle to read the incoming datagram and send
 *           the answer
 *
 * @param is information about IPsec states
 */
void ipsec_handle_datagram(int fd, ipsec_s * is) {
	socket_msg sm = { .sockfd=fd };
	ssize_t result;
	uint32_t spi = 0;
	bool is_nat_t = false;

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
			if (!ike_approve_header(sm.buf,
						result)) {
				zlog_info(zc, "IKE datagram not approved");
			}
			else {
				ike_handle_message(fd, is, sm.buf, result);
			}
		}
		else if (4500 == ds.lport) {
			is_nat_t = true;
			if (memcmp(&spi,sm.buf,4)) {
				zlog_category_t *zc = zlog_get_category("ESP");
				zlog_info(zc, "investigating NAT-T ESP datagram");
				// we don't do anything yet
				return;
			}
			else {
				zlog_category_t *zc = zlog_get_category("IKE");
				zlog_info(zc, "investigating NAT-T IKE datagram");
				if (!ike_approve_header(sm.buf+4,
							result-4)) {
					zlog_info(zc, "IKE datagram not approved");
				}
				else {
					ike_handle_message(fd, is, sm.buf+4, result-4);
				}
			}
		}
	}

	// for now send an empty IKE message back
	ike_send_datagram(&sm, is_nat_t, 0);
}// ipsec_handle_ike()
