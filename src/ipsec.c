/** \file ipsec.c
 * \brief IPsec related functions
 */
/*
 * Copyright (C) 2017-2020 Mathias Weidner <mathias@mamawe.net>
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

#include <gcrypt.h>
#include <stdbool.h>
#include <string.h>

typedef struct __attribute__((__packed__)) {
	uint64_t ispi, rspi;
	uint8_t npl;
	unsigned int min_ver:4, maj_ver:4;
	uint8_t extype, flags;
	uint32_t mid, length;
} ike_header;

#define IKE_FLAG_R(ih) (ih->flags & 0x20)
#define IKE_FLAG_V(ih) (ih->flags & 0x10)
#define IKE_FLAG_I(ih) (ih->flags & 0x08)

#define IKE_FLAG_R_SET(ih) (ih->flags |= 0x20)

#define IKE_FLAG_I_CLEAR(ih) (ih->flags &= ~0x08)

typedef struct __attribute__((__packed__)) {
	uint8_t npl;
	uint8_t flags;
	uint16_t pl_length;
} ike_gph;			// generic paylod header

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

typedef struct __attribute__((__packed__)) {
	ike_gph gph;
	uint16_t dh_group_num;
	uint16_t reserved;
} ike_ke_pl;			// key exchange payload

uint16_t ike_ke_dh_group_num(ike_ke_pl *);
uint16_t ike_ke_data_length(ike_ke_pl *);
uint8_t *ike_ke_data(ike_ke_pl *);

typedef struct __attribute__((__packed__)) {
	ike_gph gph;
	uint8_t protocol_id;
	uint8_t spi_size;
	uint16_t message_type;
} ike_notify_pl;		// notify payload

uint16_t ike_notify_message_type(ike_notify_pl *);
const char *ike_notify_message_type_name(ike_notify_pl *);
uint64_t ike_notify_spi(ike_notify_pl *);
uint8_t *ike_notify_data(ike_notify_pl *);

#define MIN_IKE_DATAGRAM_LENGTH sizeof(ike_header)

#define EXCHANGE_IKE_SA_INIT 34
#define EXCHANGE_IKE_AUTH 35
#define EXCHANGE_CREATE_CHILD_SA 36
#define EXCHANGE_INFORMATIONAL 37

#define NOTIFY_MT_UNSUPPORTED_CRITICAL_PAYLOAD 1
#define NOTIFY_MT_INVALID_IKE_SPI 4
#define NOTIFY_MT_INVALID_MAJOR_VERSION 5
#define NOTIFY_MT_INVALID_SYNTAX 7
#define NOTIFY_MT_INVALID_MESSAGE_ID 9
#define NOTIFY_MT_INVALID_SPI 11
#define NOTIFY_MT_NO_PROPOSAL_CHOSEN 14
#define NOTIFY_MT_INVALID_KE_PAYLOAD 17
#define NOTIFY_MT_AUTHENTICATION_FAILED 24
#define NOTIFY_MT_SINGLE_PAIR_REQUIRED 34
#define NOTIFY_MT_NO_ADDITIONAL_SAS 35
#define NOTIFY_MT_INTERNAL_ADDRESS_FAILURE 36
#define NOTIFY_MT_FAILED_CP_REQUIRED 37
#define NOTIFY_MT_TS_UNACCEPTABLE 38
#define NOTIFY_MT_INVALID_SELECTORS 39
#define NOTIFY_MT_TEMPORARY_FAILURE 43
#define NOTIFY_MT_CHILD_SA_NOT_FOUND 44

#define NOTIFY_MT_INITIAL_CONTACT 16384
#define NOTIFY_MT_SET_WINDOW_SIZE 16385
#define NOTIFY_MT_ADDITIONAL_TS_POSSIBLE 16386
#define NOTIFY_MT_IPCOMP_SUPPORTED 16387
#define NOTIFY_MT_NAT_DETECTION_SOURCE_IP 16388
#define NOTIFY_MT_NAT_DETECTION_DESTINATION_IP 16389
#define NOTIFY_MT_COOKIE 16390
#define NOTIFY_MT_USE_TRANSPORT_MODE 16391
#define NOTIFY_MT_HTTP_CERT_LOOKUP_SUPPORTED 16392
#define NOTIFY_MT_REKEY_SA 16393
#define NOTIFY_MT_ESP_TFC_PADDING_NOT_SUPPORTED 16394
#define NOTIFY_MT_NON_FIRST_FRAGMENTS_ALSO 16395
// RFC5685
#define NOTIFY_MT_REDIRECT_SUPPORTED 16406
// RFC7383
#define NOTIFY_MT_IKEV2_FRAGMENTATION_SUPPORTED 16430
// RFC7427
#define NOTIFY_MT_SIGNATURE_HASH_ALGORITHMS 16431

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

typedef struct {
	ikev2_transform_set value;
	char const *error;
} ikev2_transform_set_err_s;

make_err_s(ikev2_transform *, ikev2_transform);

static ikev2_transform transforms[] = {
	{.type = 1,.id = 12,.name = "aes-cbc-256",.attr.keylen = 256 },
	{.type = 1,.id = 12,.name = "aes-cbc-128",.attr.keylen = 128 },
	{.type = 2,.id = 5,.name = "prf-hmac-sha2-256" },
	{.type = 3,.id = 12,.name = "auth-hmac-sha2-256-128" },
	{.type = 4,.id = 14,.name = "modp-2048" },
	{ }			// sentinel
};				//  ikev2_transform transforms[]

typedef struct {
	uint16_t value;
	char const *name;
} ikev2_hash_algorithm;

static ikev2_hash_algorithm signature_hash_algorithms[] = {
	{0, "Reserved" },	// RFC7427
	{1, "SHA1" },		// RFC7427
	{2, "SHA2-256" },	// RFC7427
	{3, "SHA2-384" },	// RFC7427
	{4, "SHA2-512" },	// RFC7427
	{5, "Identity" },	// RFC8420
	{6, "STRIBOG_256" },	// draft-smyslov-ike2-gost-02
	{7, "STRIBOG_512" },	// draft-smyslov-ike2-gost-02
	// no sentinel here because this is only used to find the name
	// and I want the following to work:
	// sizeof(signature_hash_algorithms)/sizeof(ikev2_hash_algorithm)
};	// signature_hash_algorithms[]

/**
 * Add a payload to a buffer
 *
 * @param buf points at beginning of buffer
 *
 * @param buflen size of the buffer
 *
 * @param payload is the payload to add to the buffer
 *
 * @return pointer to the end of the payload and error condition
 */
buffer_const_err_s ike_payload_add(char *buf, size_t buflen,
				   ike_gph * const payload)
{
	buffer_const_err_s out = { };
	if (buflen < sizeof(ike_gph)) {
		out.error = "buffer too small for generic payload header";
		return out;
	}
	size_t pl_length = ntohs(payload->pl_length);
	if (pl_length < sizeof(ike_gph)) {
		out.error = "payload length less then 4";
	} else if (pl_length > buflen) {
		out.error = "payload exceeds buffer";
	} else {
		memcpy(buf, payload, pl_length);
		out.value = buf + pl_length;
	}
	return out;
}				// ike_payload_add()

/**
 * Find the last payload in a buffer
 *
 * @param buf points at a buffer containing zero or more IKE payloads
 *
 * @param buflen size of the buffer
 */
buffer_const_err_s ike_find_last_payload(unsigned char const *buf,
					 size_t buflen)
{
	buffer_const_err_s out = { };
	if (buflen < sizeof(ike_gph)) {
		out.error = "buffer too small for generic payload header";
		return out;
	}
	size_t avlen = buflen;
	ike_gph *cph = (ike_gph *) buf;
	size_t pl_length = ntohs(cph->pl_length);
	if (pl_length < sizeof(ike_gph)) {
		out.error = "payload length less then 4";
	} else if (pl_length > avlen) {
		out.error = "payload exceeds buffer";
	} else if (0 == cph->npl) {
		out.value = (char *)cph;
	}
	return out;
}				// ike_find_last_payload()

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
int ike_approve_header(unsigned char *buf, ssize_t buflen)
{
	ike_header *ih = (ike_header *) buf;
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
			   buflen, (long)ih_length);
		return 0;
	}
	if (2 != ih->maj_ver || 0 != ih->min_ver) {
		zlog_debug(zc,
			   "unknown IKE version: %d.%d",
			   ih->maj_ver, ih->min_ver);
		return 0;
	}
	switch (ih->extype) {
	case EXCHANGE_IKE_SA_INIT:
	case EXCHANGE_IKE_AUTH:
	case EXCHANGE_CREATE_CHILD_SA:
	case EXCHANGE_INFORMATIONAL:
		zlog_debug(zc, "exchange type: %hu", ih->extype);
		break;
	default:
		zlog_debug(zc, "unknown exchange type: %hu", ih->extype);
		return 0;
	}
	switch (ih->npl) {
	case NPL_NONE:
		zlog_debug(zc, "no next payload");
		break;
	case NPL_SA:
	case NPL_N:
	case NPL_D:
	case NPL_V:
	case NPL_SK:
		zlog_debug(zc, "next payload: %hu", ih->npl);
		break;
	default:
		zlog_debug(zc, "unknown next payload: %hu", ih->npl);
		return 0;
	}
	zlog_debug(zc, "IKE header OK");
	return 1;
}				// ike_approve_header()

/**
 * Approve that the payloads don't exceed the buffer and use it fully.
 *
 * @param buf points at the beginning of the first payload.
 *
 * @param buflen is the size of the buffer for all payloads.
 *
 * @param fpl is the type of the first payload.
 */
int ike_approve_payloads(unsigned char *buf, ssize_t buflen, uint8_t fpl)
{
	unsigned char *bp = buf;
	unsigned char *const ep = buf + buflen;
	uint8_t npl = fpl;
	zlog_category_t *zc = zlog_get_category("IKE");
	while (bp < ep) {
		ike_gph *ngph = (ike_gph *) bp;
		uint16_t pl_length = ntohs(ngph->pl_length);
		if (bp + pl_length > ep) {
			zlog_error(zc,
				   "length of payload %hhu exceeds buffer",
				   npl);
			return 0;
		}
		zlog_debug(zc, "payload %hhu, length: %hu", npl, pl_length);
		npl = ngph->npl;
		bp += pl_length;
		if (NPL_NONE == npl && bp < ep) {
			zlog_error(zc,
				   "no next payload but %td bytes buffer left",
				   ep - bp);
			return 0;
		} else if (NPL_NONE != npl && bp >= ep) {
			zlog_error(zc,
				   "next payload %hhu but no bytes in buffer",
				   npl);
			return 0;
		}
	}
	return 1;
}				// ike_approve_payloads()

/**
 * Return char array containing name of protocol ID in proposal.
 *
 * @param protocol_id protocol ID in proposal from SA payload
 */
const char *ike_protocol_id_name(uint8_t protocol_id)
{
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
}				// ike_protocol_id_name()

/**
 * Return char array containing name of transform type in proposal.
 *
 * @param type - transform type from proposal
 */
const char *ike_transform_type_name(uint8_t type)
{
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
}				// ike_transform_type_name()

/**
 * Return char array containing name of ENCR transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char *ike_transform_encr_name(uint16_t id)
{
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
}				// ike_transform_encr_name()

/**
 * Return char array containing name of PFR transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char *ike_transform_prf_name(uint16_t id)
{
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
}				// ike_transform_prf_name()

/**
 * Return char array containing name of INTEG transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char *ike_transform_integ_name(uint16_t id)
{
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
}				// ike_transform_integ_name()

/**
 * Return char array containing name of DH transform ID.
 *
 * @param id - ID from transform
 *
 * see http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
 */
const char *ike_transform_dh_name(uint16_t id)
{
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
}				// ike_transform_dh_name()

/**
 * Return char array containing name of ESN ID in transform in proposal.
 *
 * @param id - ID from transform
 */
const char *ike_transform_esn_name(uint16_t id)
{
	switch (id) {
	case 0:
		return "no ESN";
	case 1:
		return "ESN";
	default:
		return "unknown ESN";
	}
}				// ike_transform_esn_name()

/**
 * Return char array containing name of protocol ID in proposal.
 *
 * @param transform_type - type of transform (ENCR, PRF, INTEG, DH, ESN)
 *
 * @param id - transform ID
 */
const char *ike_transform_id_name(uint8_t transform_type, uint16_t id)
{
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
}				// ike_transform_id_name()

int ike_transform_equal_attr(ike_sa_transform * tf, ikev2_transform * tp)
{
	int ret = 0;
	ike_sa_tf_attribute *ap = (ike_sa_tf_attribute *) (tf + 1);
	uint16_t attr_type = ntohs(ap->format_type);
	if ((attr_type & 0x8000)
	    && 14 == (attr_type & 0x7fff)) {
		ret = (tp->attr.keylen == ntohs(ap->length_value));
	}
	return ret;
}				// ike_transform_equal_attr()

ikev2_transform_err_s ike_find_transform(unsigned char *buf, size_t buflen,
					 int tnum)
{
	ikev2_transform_err_s out = { };
	if (buflen < sizeof(ike_sa_transform)) {
		out.error = "buffer to short for transform";
	} else {
		ike_sa_transform *tf = (ike_sa_transform *) buf;
		uint16_t tf_length = ntohs(tf->transform_length);
		uint16_t tf_id = ntohs(tf->transform_id);
		ikev2_transform *tp = transforms;
		while (0 != tp->type) {
			if (tp->type == tf->transform_type && tp->id == tf_id) {
				if ((sizeof(ike_sa_transform) == tf_length)
				    || ike_transform_equal_attr(tf, tp)) {
					out.value = tp;
					break;
				}
			}
			tp++;
		}
		if (0 == out.value) {
			out.error = "unknown transform";
		}
	}
	return out;
}				// ike_find_transform()

/**
 * parse transforms in proposals in SA payload
 *
 * @param buf - buffer containing transforms
 *
 * @param buflen - length of buffer
 *
 * @num_transforms - number of expected transforms
 *
 * TODO: return ikev2_transform_set_err
 */
ikev2_transform_set_err_s ike_parse_transforms(unsigned char *buf,
					       ssize_t buflen,
					       int num_transforms)
{

	ikev2_transform_set_err_s out = {.value = { } };
	unsigned char *bp = buf;
	const unsigned char *ep = buf + buflen;
	zlog_category_t *zc = zlog_get_category("IKE");
	int transform_number = 1;
	while (transform_number <= num_transforms) {
		if (ep < bp + sizeof(ike_sa_transform)) {
			zlog_error(zc, "buffer to short for transform %u",
				   transform_number);
			out.error = "buffer to short for transform";
			return out;
		}
		ike_sa_transform *tf = (ike_sa_transform *) bp;
		uint16_t tf_length = ntohs(tf->transform_length);
		ikev2_transform_err_s te = ike_find_transform(bp,
							      tf_length,
							      transform_number);
		if (te.error) {
			zlog_error(zc, " transform: #%u [%hhu]: %s",
				   transform_number, tf_length, te.error);
		} else {
			uint16_t tf_id = ntohs(tf->transform_id);
			zlog_info(zc,
				  "  transform #%u [%hhu]: %s (%hhu): %s (%hu)",
				  transform_number,
				  tf_length,
				  ike_transform_type_name(tf->transform_type),
				  te.value->type, te.value->name, te.value->id);
			// add transform to transform set
			if (1 == tf->transform_type) {
				out.value.encr = te.value;
			} else if (2 == tf->transform_type) {
				out.value.prf = te.value;
			} else if (3 == tf->transform_type) {
				out.value.integ = te.value;
			} else if (4 == tf->transform_type) {
				out.value.dh = te.value;
			} else if (5 == tf->transform_type) {
				out.value.esn = te.value;
			}
		}
		bp += tf_length;
		++transform_number;
	}
	return out;
}				// ike_parse_transforms()

int ike_parse_sa_payload(unsigned char *buf, ssize_t buflen, ipsec_sa * sa)
{
	unsigned char *bp = buf;
	const unsigned char *ep = buf + buflen;
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "SA payload [%lu]", buflen);
	while (ep > bp + sizeof(ike_sa_proposal)) {
		ike_sa_proposal *prop = (ike_sa_proposal *) bp;
		uint16_t prop_length = ntohs(prop->proposal_length);
		zlog_info(zc,
			  " proposal #%hhu [%hhu]: protocol: %s (%hhu), SPI size %hhu, %hhu transforms",
			  prop->proposal_num,
			  prop_length,
			  ike_protocol_id_name(prop->protocol_id),
			  prop->protocol_id,
			  prop->spi_size, prop->num_transforms);
		sa->spid = prop->protocol_id;
		ikev2_transform_set_err_s tse;
		tse = ike_parse_transforms(bp + sizeof(ike_sa_proposal),
					   prop_length -
					   sizeof(ike_sa_proposal),
					   prop->num_transforms);
		if (tse.error) {
			zlog_error(zc, "problem parsing proposal %hhu: %s",
				   prop->proposal_num, tse.error);
			return 0;
		}
		if (NULL == sa->transform.encr) {
			// take the first transform and no other
			memcpy(&sa->transform, &tse.value,
			       sizeof(sa->transform));
		}
		if (ep == bp + prop_length) {
			if (0 == prop->last_substruct) {
				return 1;
			} else {
				zlog_info(zc,
					  "last substruct not set at end of SA payload");
				return 0;
			}
		}
		if (0 == prop->last_substruct) {
			zlog_info(zc,
				  "last substruct set but not end of SA payload");
			return 0;
		}
		bp += prop_length;
	}
	zlog_info(zc, "proposal exceeds SA payload by %ld bytes", bp - ep);
	return 0;
}				// ike_parse_sa_payload()

/**
 * Return DH group number
 *
 * @param ke key exchange payload
 */
uint16_t ike_ke_dh_group_num(ike_ke_pl * kepl)
{
	return ntohs(kepl->dh_group_num);
}				// ike_ke_dh_group_num()

/**
 * Get size of key exchange data
 *
 * @param kepl pointer to KE payload
 *
 * return size of key exchange data or 0 if KE payload is too small
 */
uint16_t ike_ke_data_length(ike_ke_pl * kepl)
{
	uint16_t pl_length = ntohs(kepl->gph.pl_length);
	if (pl_length > sizeof(kepl)) {
		return (pl_length - sizeof(kepl));
	}
	return 0;
}				// ike_ke_data_length()

/**
 * Get key exchange data
 *
 * @param kepl pointer ot KE payload
 *
 * @return pointer to buffer or NULL if size of KE payload is too small
 */
uint8_t *ike_ke_data(ike_ke_pl * kepl)
{
	uint16_t pl_length = ntohs(kepl->gph.pl_length);
	if (pl_length > sizeof(kepl)) {
		uint8_t *data = (uint8_t *) kepl;
		return (data + sizeof(kepl));
	}
	return NULL;
}				// ike_ke_data()

/**
 * Parse Key Exchange Payload
 *
 * @param buf a buffer containing the payload
 *
 * @param buflen the length of the buffer
 *
 * @return 1 for success, 0 for failure
 */
int ike_parse_ke_payload(unsigned char *buf, ssize_t buflen, ipsec_sa * sa)
{
	ike_ke_pl *kepl = (ike_ke_pl *) buf;
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "KE payload [%lu]", buflen);
	if (buflen <= sizeof(ike_ke_pl)) {
		zlog_info(zc, "buffer too small for Key Exchange Payload");
		return 0;
	}
	zlog_info(zc,
		  " DH group %hu, %hu byte key exchange data",
		  ike_ke_dh_group_num(kepl), ike_ke_data_length(kepl));
	if (ike_ke_dh_group_num(kepl) == sa->transform.dh->id) {
		memcpy(&sa->key, buf + sizeof(ike_ke_pl),
		       ike_ke_data_length(kepl));
	} else {
		zlog_info(zc,
			  "wrong KE payload, expected %hu got %hu",
			  sa->transform.dh->id, ike_ke_dh_group_num(kepl));
		return 0;
	}
	return 1;
}				// ike_parse_ke_payload()

/**
 * Parse Nonce Payload
 *
 * @param buf a buffer containing the payload
 *
 * @param buflen the length of the buffer
 *
 * @return 1 for success, 0 for failure
 */
int ike_parse_nonce_payload(unsigned char *buf, ssize_t buflen, ipsec_sa * sa)
{
	ike_gph *nph = (ike_gph *) buf;
	uint16_t nonce_len = ntohs(nph->pl_length) - sizeof(ike_gph);
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "Nonce payload [%lu]", buflen);
	if (buflen < 16 + sizeof(ike_gph)) {
		zlog_info(zc, "buffer too small for nonce payload");
		return 0;
	}
	if (buflen < nonce_len + sizeof(ike_gph)) {
		zlog_info(zc,
			  "buffer too small for nonce payload of %hu bytes",
			  nonce_len);
		return 0;
	}
	sa->nonce.length = nonce_len;
	memcpy(&sa->nonce.data, buf + sizeof(ike_gph), nonce_len);
	zlog_info(zc, " %hu byte nonce data", nonce_len);
	return 1;
}				// ike_parse_nonce_payload()

/**
 * Address is translated
 *
 * @param spis buffer chunk containing SPIs of the datagram
 *
 * @param address buffer chunk containing source or destination address
 *
 * @param port buffer chunk containing source or destination port
 *
 * @param sha1 buffer chunk containing SHA1 digest sent by peer
 */
int ike_notify_address_translated(unsigned char *spis_ptr,
				  chunk_t address,
				  unsigned char *port_ptr,
				  unsigned char *sha1_ptr)
{
	zlog_category_t *zc = zlog_get_category("CRYPT");
	gcry_error_t gerr;
	gcry_md_hd_t hd;
	int algo = GCRY_MD_SHA1;
	int result = 0;
	chunk_t spis = {.ptr = spis_ptr,.len = 16 };
	chunk_t port = {.ptr = port_ptr,.len = 2 };
	chunk_t sha1 = {.ptr = sha1_ptr,.len = 20 };

	gerr = gcry_md_open(&hd, algo, 0);
	if (gerr) {
		zlog_error(zc,
			   "algo %d, gcry_md_open failed: %s",
			   algo, gpg_strerror(gerr));
		exit(1);
	}
	gcry_md_write(hd, spis.ptr, spis.len);
	gcry_md_write(hd, address.ptr, address.len);
	gcry_md_write(hd, port.ptr, port.len);
	unsigned char *hash = gcry_md_read(hd, algo);
	if (memcmp(hash, sha1.ptr, sha1.len)) {
		zlog_debug(zc, "hash digests differ");
		result = 1;
	}
	gcry_md_close(hd);
	return result;
}				// ike_notify_address_translated()

uint16_t ike_notify_message_type(ike_notify_pl * npl)
{
	return ntohs(npl->message_type);
}				// ike_notify_message_type()

const char *ike_notify_message_type_name(ike_notify_pl * npl)
{
	uint16_t msgtype = ike_notify_message_type(npl);
	switch (msgtype) {
	case NOTIFY_MT_UNSUPPORTED_CRITICAL_PAYLOAD:
		return "UNSUPPORTED_CRITICAL_PAYLOAD";
	case NOTIFY_MT_INVALID_IKE_SPI:
		return "INVALID_IKE_SPI";
	case NOTIFY_MT_INVALID_MAJOR_VERSION:
		return "INVALID_MAJOR_VERSION";
	case NOTIFY_MT_INVALID_SYNTAX:
		return "INVALID_SYNTAX";
	case NOTIFY_MT_INVALID_MESSAGE_ID:
		return "INVALID_MESSAGE_ID";
	case NOTIFY_MT_INVALID_SPI:
		return "INVALID_SPI";
	case NOTIFY_MT_NO_PROPOSAL_CHOSEN:
		return "NO_PROPOSAL_CHOSEN";
	case NOTIFY_MT_INVALID_KE_PAYLOAD:
		return "INVALID_KE_PAYLOAD";
	case NOTIFY_MT_AUTHENTICATION_FAILED:
		return "AUTHENTICATION_FAILED";
	case NOTIFY_MT_SINGLE_PAIR_REQUIRED:
		return "SINGLE_PAIR_REQUIRED";
	case NOTIFY_MT_NO_ADDITIONAL_SAS:
		return "NO_ADDITIONAL_SAS";
	case NOTIFY_MT_INTERNAL_ADDRESS_FAILURE:
		return "INTERNAL_ADDRESS_FAILURE";
	case NOTIFY_MT_FAILED_CP_REQUIRED:
		return "FAILED_CP_REQUIRED";
	case NOTIFY_MT_TS_UNACCEPTABLE:
		return "TS_UNACCEPTABLE";
	case NOTIFY_MT_INVALID_SELECTORS:
		return "INVALID_SELECTORS";
	case NOTIFY_MT_TEMPORARY_FAILURE:
		return "TEMPORARY_FAILURE";
	case NOTIFY_MT_CHILD_SA_NOT_FOUND:
		return "CHILD_SA_NOT_FOUND";
	case NOTIFY_MT_INITIAL_CONTACT:
		return "INITIAL_CONTACT";
	case NOTIFY_MT_SET_WINDOW_SIZE:
		return "SET_WINDOW_SIZE";
	case NOTIFY_MT_ADDITIONAL_TS_POSSIBLE:
		return "ADDITIONAL_TS_POSSIBLE";
	case NOTIFY_MT_IPCOMP_SUPPORTED:
		return "IPCOMP_SUPPORTED";
	case NOTIFY_MT_NAT_DETECTION_SOURCE_IP:
		return "NAT_DETECTION_SOURCE_IP";
	case NOTIFY_MT_NAT_DETECTION_DESTINATION_IP:
		return "NAT_DETECTION_DESTINATION_IP";
	case NOTIFY_MT_COOKIE:
		return "COOKIE";
	case NOTIFY_MT_USE_TRANSPORT_MODE:
		return "USE_TRANSPORT_MODE";
	case NOTIFY_MT_HTTP_CERT_LOOKUP_SUPPORTED:
		return "HTTP_CERT_LOOKUP_SUPPORTED";
	case NOTIFY_MT_REKEY_SA:
		return "REKEY_SA";
	case NOTIFY_MT_ESP_TFC_PADDING_NOT_SUPPORTED:
		return "ESP_TFC_PADDING_NOT_SUPPORTED";
	case NOTIFY_MT_NON_FIRST_FRAGMENTS_ALSO:
		return "NON_FIRST_FRAGMENTS_ALSO";
	case NOTIFY_MT_REDIRECT_SUPPORTED:
		return "REDIRECT_SUPPORTED";
	case NOTIFY_MT_IKEV2_FRAGMENTATION_SUPPORTED:
		return "IKEV2_FRAGMENTATION_SUPPORTED";
	case NOTIFY_MT_SIGNATURE_HASH_ALGORITHMS:
		return "SIGNATURE_HASH_ALGORITHMS";
	default:
		return "UNKNOWN_MESSAGE_TYPE";
	}
}				// ike_notify_message_type_name()

/**
 * Parse Notify Payload
 *
 * @param buf a buffer containing the payload
 *
 * @param buflen the length of the buffer
 *
 * @return 1 for success, 0 for failure
 */
int ike_parse_notify_payload(unsigned char *buf,
			     ssize_t buflen, ipsec_sa * sa, socket_msg * sm)
{
	ike_notify_pl *npl = (ike_notify_pl *) buf;
	uint16_t notify_len = ntohs(npl->gph.pl_length);
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "Notify payload [%lu]", buflen);
	if (buflen < sizeof(ike_notify_pl)) {
		zlog_info(zc, "buffer too small for notify payload");
		return 0;
	}
	if (buflen < notify_len) {
		zlog_info(zc,
			  "buffer too small for notify payload of %hu bytes",
			  notify_len);
		return 0;
	}
	uint16_t nmt = ike_notify_message_type(npl);
	zlog_info(zc,
		  " notify %s (%hu) with %hu byte length",
		  ike_notify_message_type_name(npl), nmt, notify_len);
	if (NOTIFY_MT_NAT_DETECTION_SOURCE_IP == nmt) {
		if (ike_notify_address_translated(sm->buf,
						  sm->ds->raddress,
						  (unsigned char *)&sm->ds->
						  rportn,
						  buf +
						  sizeof(ike_notify_pl))) {
			sa->options.snat = 1;
			zlog_info(zc, "  NAT detected");
		} else {
			zlog_info(zc, "  no NAT detected");
		}
	}
	if (NOTIFY_MT_NAT_DETECTION_DESTINATION_IP == nmt) {
		if (ike_notify_address_translated(sm->buf,
						  sm->ds->laddress,
						  (unsigned char *)&sm->ds->
						  lportn,
						  buf +
						  sizeof(ike_notify_pl))) {
			sa->options.dnat = 1;
			zlog_info(zc, "  NAT detected");
		} else {
			zlog_info(zc, "  no NAT detected");
		}
	}
	if (NOTIFY_MT_IKEV2_FRAGMENTATION_SUPPORTED == nmt) {
		// see https://datatracker.ietf.org/doc/html/rfc7383#section-2.3
		sa->options.fragmentation_supported = 1;
	}
	if (NOTIFY_MT_SIGNATURE_HASH_ALGORITHMS == nmt) {
		// see https://datatracker.ietf.org/doc/html/rfc7427#section-4
		//
		// The Notification Data field contains the list of 16-bit hash
		// algorithm identifiers from the Hash Algorithm Identifiers of IANA's
		// "Internet Key Exchange Version 2 (IKEv2) Parameters" registry.  There
		// is no padding between the hash algorithm identifiers.
		// TODO: pick an algorithm
		uint16_t *shap = (uint16_t *)(npl+1);
		for (int i = 0; i < (notify_len - sizeof(ike_notify_pl))/2; i++) {
			int ha = ntohs(shap[i]);
			if (ha < sizeof(signature_hash_algorithms)/sizeof(ikev2_hash_algorithm)) {
				zlog_info(zc, "  HASH_ALGORITHM: %hu (%s)",
					  ha, signature_hash_algorithms[ha].name);
			}
			else {
				zlog_debug(zc,
					   "unknown signature hash algorithm: %hu",
					   ha);
			}
		}
	}
	if (NOTIFY_MT_REDIRECT_SUPPORTED == nmt) {
		// TODO
	}
	return 1;
}				// ike_parse_notify_payload()

/**
 * Return char array containing name of exchange type.
 *
 * @param extype binary IKE exchange type
 */
const char *ike_exchange_name(uint8_t extype)
{
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
}				// ike_exchange_name()

/**
 * Handle an IKE_SA_INIT exchange.
 *
 * @param sm the socket_msg connected to the incoming datagram.
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
void ike_hm_ike_sa_init(socket_msg * sm, ipsec_s * is,
			unsigned char *buf, ssize_t buflen)
{
	int fd = sm->sockfd;
	ike_header *ih = (ike_header *) buf;
	zlog_category_t *zc = zlog_get_category("IKE");
	zlog_info(zc, "handling IKE_SA_INIT");
	uint8_t npl = ih->npl;
	unsigned char *const ep = buf + buflen;
	unsigned char *bp = buf + sizeof(ike_header);
	if (!ike_approve_payloads(bp, buflen - sizeof(ike_header), npl)) {
		zlog_error(zc, "payloads not approved");
		return;
	}
	// TODO: add sa.daddr, sa.saddr
	ipsec_sa sa = {.spi = ih->ispi,.spid = IKEv2_SPID_IKE };
	memcpy(&sa.daddr, &sm->ds->laddr, sizeof(sa.daddr));
	memcpy(&sa.pdaddr, &sm->ds->pladdr, sizeof(sa.pdaddr));
	memcpy(&sa.saddr, &sm->ds->raddr, sizeof(sa.saddr));
	memcpy(&sa.psaddr, &sm->ds->praddr, sizeof(sa.psaddr));
	while (bp < ep) {
		ike_gph *ngph = (ike_gph *) bp;
		uint16_t pl_length = ntohs(ngph->pl_length);
		switch (npl) {
		case 33:	// Security Association (SA)
			if (ike_parse_sa_payload(bp + sizeof(ike_gph),
						 pl_length - sizeof(ike_gph),
						 &sa)) {
				// TODO: use SA payload
			}
			break;
		case 34:	// Key Exchange
			if (ike_parse_ke_payload(bp, pl_length, &sa)) {
				// TODO: use KE payload
			}
			break;
		case 40:	// Nonce
			if (ike_parse_nonce_payload(bp, pl_length, &sa)) {
				// TODO: use KE payload
			}
			break;
		case 41:	// Notify
			if (ike_parse_notify_payload(bp, pl_length, &sa, sm)) {
				// TODO: use KE payload
			}
			break;
			// TODO: parse other payloads
		default:
			zlog_info(zc,
				  "don't know how to handle payload %hhu", npl);
		}
		npl = ngph->npl;
		bp += pl_length;
	}
	ipsec_sa_err_s insert = sad_put_record(&sa);
	if (insert.error) {
		zlog_error(zc, "could not add record to SAD: %s", insert.error);
		return;
	} else {
		uint64_t reverse_spi = ~sa.spi;
		insert = sad_add_reverse_record(&sa, reverse_spi);
		if (insert.error) {
			zlog_error(zc,
				   "could not add reverse record to SAD: %s",
				   insert.error);
			return;
		}
	}
	buffer_const_err_s result;
	result = ike_response_ike_sa_init(buf, buflen, NULL);
}				// ike_hm_ike_sa_init()

/**
 * Handle an already approved IKE message
 *
 * @param fd the socket_msg connected the incoming datagram
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
void ike_handle_message(socket_msg * sm, ipsec_s * is,
			unsigned char *buf, ssize_t * buflen)
{
	int fd = sm->sockfd;
	ike_header *ih = (ike_header *) buf;
	uint32_t ih_length = ntohl(ih->length);
	zlog_category_t *zc = zlog_get_category("IKE");
	char ibuf[17];

	zlog_info(zc,
		  "IKE %d.%d iSPI:%s, rSPI:%s, MID: %ld",
		  ih->maj_ver,
		  ih->min_ver,
		  bytearray_to_string((char *)&ih->ispi, 8, ibuf, sizeof(ibuf)),
		  bytearray_to_string((char *)&ih->ispi, 8, ibuf, sizeof(ibuf)),
		  (unsigned long)ntohl(ih->mid));
	zlog_info(zc,
		  " exchange type: %s, flags %hhX",
		  ike_exchange_name(ih->extype), ih->flags);
	switch (ih->extype) {
	case EXCHANGE_IKE_SA_INIT:
		ike_hm_ike_sa_init(sm, is, buf, *buflen);
		*buflen = 0;
		break;
	case EXCHANGE_IKE_AUTH:
	case EXCHANGE_CREATE_CHILD_SA:
	case EXCHANGE_INFORMATIONAL:
	default:
		zlog_info(zc,
			  "can't handle %s message yet",
			  ike_exchange_name(ih->extype));
	}
	// for now just set the responder flag
	// and clear the intiator flag
	IKE_FLAG_R_SET(ih);
	IKE_FLAG_I_CLEAR(ih);
}				// ike_handle_message()

/**
 * Adjust the IKE header and send the datagram
 *
 * @param psm pointer to socket_msg used to send the datagram
 *
 * @param is_nat_t the datagram uses NAT-T
 *
 * @param length the length of the IKE payload excluding the IKE header
 */
ssize_t ike_send_datagram(socket_msg * psm, bool is_nat_t, ssize_t length)
{
	ike_header *ih;
	ssize_t dglen = 0;

	if (is_nat_t) {
		dglen += 4;
		ih = (ike_header *) (psm->buf + 4);
	} else {
		ih = (ike_header *) (psm->buf);
	}
	dglen += ntohl(ih->length);
	psm->msg.msg_iov[0].iov_len = dglen;
	return socket_sendmsg(psm);
}				// ike_send_datagram()

/**
 * Handle the IPsec datagram
 *
 * @param fd the socket handle to read the incoming datagram and send
 *           the answer
 *
 * @param is information about IPsec states
 */
void ipsec_handle_datagram(int fd, ipsec_s * is)
{
	socket_msg sm = {.sockfd = fd };
	ssize_t dglen;
	uint32_t spi = 0;
	bool is_nat_t = false;

	char mdc_buf[5];
	unsigned int mdc_cnt = ++(is->mdc_counter);
	snprintf(mdc_buf, sizeof(mdc_buf), "%4.4x", mdc_cnt);
	zlog_put_mdc("dg", mdc_buf);

	if (0 >= (dglen = socket_recvmsg(&sm))) {
		return;
	}

	datagram_spec ds = { };
	get_ds(&ds, &sm);
	sm.ds = &ds;
	unsigned char *sm_buf = sm.buf;

	if (SOCK_DGRAM == ds.so_type) {
		if (500 == ds.lport) {
			zlog_category_t *zc = zlog_get_category("IKE");
			zlog_debug(zc, "investigating IKE datagram");
			if (!ike_approve_header(sm.buf, dglen)) {
				zlog_info(zc, "IKE datagram not approved");
				return;
			}
		} else if (4500 == ds.lport) {
			is_nat_t = true;
			if (memcmp(&spi, sm.buf, 4)) {
				zlog_category_t *zc = zlog_get_category("ESP");
				zlog_info(zc,
					  "investigating NAT-T ESP datagram");
				// this is an ESP datagram
				return;
			} else {
				zlog_category_t *zc = zlog_get_category("IKE");
				zlog_info(zc,
					  "investigating NAT-T IKE datagram");
				if (!ike_approve_header(sm.buf + 4, dglen - 4)) {
					zlog_info(zc,
						  "IKE datagram not approved");
					return;
				} else {
					sm_buf = sm.buf + 4;
					dglen -= 4;
				}
			}
		}
		ike_handle_message(&sm, is, sm_buf, &dglen);
		ike_send_datagram(&sm, is_nat_t, dglen);
	}

}				// ipsec_handle_datagram()

buffer_const_err_s ike_response_ike_sa_init(unsigned char *buf,
					    size_t buflen, ipsec_sa * peer)
{
	buffer_const_err_s result = {.error = "not implemented yet" };

	if (NULL == peer) {
		return ike_response_no_proposal_chosen(buf, buflen);
	}
	return result;
}				// ike_response_ike_sa_init()

buffer_const_err_s ike_response_no_proposal_chosen(unsigned char *buf,
						   size_t buflen)
{
	buffer_const_err_s result;
	ike_header *ih = (ike_header *) buf;
	ike_notify_pl answer = {.gph.npl = 0,.gph.pl_length = htons(8),
		.protocol_id = 1,.message_type = htons(14)
	};
	result = ike_payload_add(buf + sizeof(ike_header),
				 buflen - sizeof(ike_header),
				 (ike_gph *) & answer);
	ih->npl = 41;
	ih->length = htonl(36);
	return result;
}
