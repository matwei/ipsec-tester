/*
 * datastore.c
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

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "datastore.h"

int mkdirunder(const char * basedir, const char * path) {
	int result = 0;
	int len = strlen(basedir) + strlen(path) + 2;
	char *dir = malloc(len);
	char *pathc = strdup(path);
	char *token;
	struct stat buffer = {};

	strcpy(dir,basedir);
	token = strtok(pathc,"/");
	while (token = strtok(NULL,"/")) {
		strcat(dir,"/");
		strcat(dir,token);
		if (stat(dir,&buffer)) {
			// printf("mkdir %s\n", dir);
			mkdir(dir,0777);
		}
	}
mkdirunder_end:
	if (dir) free(dir);
	if (pathc) free(pathc);
	return result;
} // mkdirunder()

datastore_s ds_load(const char * basedir) {
	datastore_s ds = {};
	struct stat buffer = {};

	if(stat(basedir, &buffer)) {
		ds.error = (ENOENT == errno) ? "ds_load: basedir doesn't exist"
			 :                     "ds_load: stat() failed";
	}
	else if (! S_ISDIR(buffer.st_mode)) {
		ds.error = "ds_load: basedir not a directory";
	}
	else {
		ds.basedir = basedir;
	}
	return ds;
} // ds_load()

peer_s ds_init_peer_ip(const datastore_s ds, const char * peer) {
	peer_s ps = {};
	struct addrinfo hints = { .ai_family=AF_UNSPEC, .ai_socktype=SOCK_DGRAM };
	struct addrinfo *result;
	int status;

	status = getaddrinfo(peer, "isakmp", &hints, &result);
	if (0 != status) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		ps.error = "ds_init_peer: getaddrinfo failed";
		return ps;
	}
	struct sockaddr *sa = (struct sockaddr *)result->ai_addr;
	switch (sa->sa_family) {
		case AF_INET:
			snprintf(ps.path,MAX_DS_PEER_PATH,
					"ip4/%02x/%02x/%02x/%02x",
					(int)sa->sa_data[2],
					(int)sa->sa_data[3],
					(int)sa->sa_data[4],
					(int)sa->sa_data[5]
					);
			break;
		case AF_INET6:
			snprintf(ps.path,MAX_DS_PEER_PATH,
					"ip6/%02x%02x/%02x%02x/%02x%02x/%02x%02x"
					"/%02x%02x/%02x%02x/%02x%02x/%02x%02x",
					(int)sa->sa_data[6],  (int)sa->sa_data[7],
					(int)sa->sa_data[8],  (int)sa->sa_data[9],
					(int)sa->sa_data[10], (int)sa->sa_data[11],
					(int)sa->sa_data[12], (int)sa->sa_data[13],
					(int)sa->sa_data[14], (int)sa->sa_data[15],
					(int)sa->sa_data[16], (int)sa->sa_data[17],
					(int)sa->sa_data[18], (int)sa->sa_data[19],
					(int)sa->sa_data[20], (int)sa->sa_data[21]
					);
			break;
		default:
			ps.error = "ds_init_peer_ip: unknown address family";
	}
	//printf("ds_init_peer: int %s\n", ps.path);
	mkdirunder(ds.basedir,ps.path);
	return ps;
} // ds_init_peer_ip()

