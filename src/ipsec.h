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

#endif /* !IPSEC_H */
