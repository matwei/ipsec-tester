/** \file datastore.h
 * \brief definitions for the data store (DH)
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

#ifndef DATASTORE_H
#define DATASTORE_H

#include <sys/socket.h>

/**
 * \brief DS handle
 */
typedef struct datastore_s {
	char const * basedir;
	char const * error;
} datastore_s;

#define MAX_DS_PEER_PATH 256

/**
 * \brief handle for a peer storage
 */
typedef struct peer_s {
	char path[MAX_DS_PEER_PATH];
	char const * error;
} peer_s;

datastore_s ds_load(const char *);

peer_s ds_get_peer(const datastore_s, struct sockaddr *);
peer_s ds_init_peer_ip(const datastore_s, const char *);

char * ds_fname_peer(const datastore_s, peer_s, char *, size_t, const char *);
char * ds_fname_sa(const datastore_s, struct sockaddr *, char *, size_t, const char *);

#endif /* !DATASTORE_H */
