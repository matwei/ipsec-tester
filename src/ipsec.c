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
		}
		else if (4500 == ds.lport) {
			if (memcmp(&spi,sm.buf,4)) {
				zlog_category_t *zc = zlog_get_category("ESP");
				zlog_info(zc, "investigating NAT-T ESP datagram");
			}
			else {
				zlog_category_t *zc = zlog_get_category("IKE");
				zlog_info(zc, "investigating NAT-T IKE datagram");
			}
		}
	}

	// for now send the datagramm back as echo
	sm.msg.msg_iov[0].iov_len= result;
	socket_sendmsg(&sm);
}// ipsec_handle_ike()
