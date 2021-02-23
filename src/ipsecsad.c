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

#include <gmodule.h>
#include <stdlib.h>
#include <string.h>

static GList * sad;

static gint ipsec_sa_compare(gconstpointer a,
                             gconstpointer b) {
	ipsec_sa * sa_a = (ipsec_sa *)a;
	ipsec_sa * sa_b = (ipsec_sa *)b;

	return memcmp(&sa_a->spi, &sa_b->spi, sizeof(sa_a->spi));
} // ipsec_sa_compare()

/**
 * get an SAD record for the given peer
 *
 * @param is - the ipsec instance
 *
 * @param peer - a template structure for an IPsec peer
 *
 * @return - the filled in template and an error condition
 */
ipsec_sa_err_s sad_get_record(ipsec_s *is,  ipsec_sa *peer) {
	ipsec_sa_err_s out = {};
	ipsec_sa * sa_a = (ipsec_sa *)peer;
	GList * cur = g_list_first(sad);
	do {
		ipsec_sa * sa_b = (ipsec_sa *)cur->data;
		if (0 == memcmp(&sa_a->spi, &sa_b->spi, sizeof(sa_a->spi))) {
			out.value = cur->data;
			break;
		}
	} while (cur = cur->next);
	return out;
} // sad_get_record()

ipsec_sa_err_s sad_del_record(ipsec_s *is,  ipsec_sa *peer) {
	ipsec_sa_err_s out = sad_get_record(is, peer);

	if (out.value) {
		free(out.value);
		out.value = 0;
	}
	return out;
} // sad_del_record()

/**
 * put a record into SAD
 *
 * @param is - the ipsec instance
 *
 * @param peer - the peer record
 *
 * @return - an error condition
 */
ipsec_sa_err_s sad_put_record(ipsec_s *is,  ipsec_sa *peer) {
	ipsec_sa_err_s out = { .value=malloc(sizeof(ipsec_sa)) };

	if (out.value) {
		sad = g_list_insert_sorted(sad,
		                           out.value,
				           ipsec_sa_compare);
		// TODO: What happens when item can't be inserted?
	}
	else {
		out.error = "could not allocate memory for SA record";
	}
	return out;
} // sad_put_record()

void sad_destroy() {
	g_list_free_full(g_steal_pointer(&sad), free);
} // sad_destroy()
