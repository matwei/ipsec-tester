/** \file ipsecsad.c
 * \brief functions concerning the IPsec SAD
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

#include <string.h>

static ipsec_sa just_one_peer = {};

/**
 * get an SAD record for the given peer
 *
 * @param is - the ipsec instance
 *
 * @param peer - a template structure for an IPsec peer
 *
 * @return - the filled in template and an error condition
 */
ipsec_sa_err_s sad_get_peer_record(ipsec_s *is,  ipsec_sa *peer) {
	ipsec_sa_err_s out = { .value=peer };
	if (memcmp(peer->raddr,just_one_peer.raddr,sizeof(just_one_peer.raddr))
		&& peer->rport != just_one_peer.rport) {
		out.error = "peer not found";
	}
	else {
		memcpy(peer,&just_one_peer, sizeof(just_one_peer));
	}
	return out;
} // sad_get_peer_record()

/**
 * put a record back into SAD
 *
 * @param is - the ipsec instance
 *
 * @param peer - the peer record
 *
 * @return - an error condition
 */
ipsec_sa_err_s sad_put_peer_record(ipsec_s *is,  ipsec_sa *peer) {
	ipsec_sa_err_s out = { .value=peer };

	memcpy(&just_one_peer, peer, sizeof(just_one_peer));
	return out;
} // sad_put_peer_record()
