/*
 * ipsec.h
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

#include <sys/types.h>

#include "datastore.h"

typedef void (*ipsec_handler)(u_char *, const u_char *, size_t, datastore_s);

void handle_ipsec(u_char *, const u_char *, size_t, datastore_s);

#endif /* !IPSEC_H */
