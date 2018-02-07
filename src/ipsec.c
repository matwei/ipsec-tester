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

#include <stdio.h>

#include "ipsec.h"

void handle_ipsec(const u_char *packet, size_t psize, datastore_s *ds) {
	printf("handle_ipsec()\n");
	return;
} // handle_ipsec()

void ipsec_handle_ike(int fd) {
	printf("ipsec_handle_ike()\n");
	return;
}// ipsec_handle_ike()
