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

typedef struct {
	char * value;
	char const * error;
} string_err_s;

static string_err_s add_address_path (datastore_s ds, struct sockaddr * sa, char * buf, size_t buflen) {
	string_err_s out = {.value=buf};
	char path[MAX_DS_PEER_PATH];
	strncpy(out.value,ds.basedir,MAX_DS_PEER_PATH);
	strncat(out.value,"/",MAX_DS_PEER_PATH - strlen(out.value));
	int len = MAX_DS_PEER_PATH - strlen(out.value);
	switch (sa->sa_family) {
		case AF_INET:
			snprintf(path,len,
					"ip4/%02hhx/%02hhx/%02hhx/%02hhx",
					sa->sa_data[2], sa->sa_data[3],
					sa->sa_data[4], sa->sa_data[5]
					);
			break;
		case AF_INET6:
			snprintf(path,len,
					"ip6/%02hhx%02hhx/%02hhx%02hhx"
					"/%02hhx%02hhx/%02hhx%02hhx"
					"/%02hhx%02hhx/%02hhx%02hhx"
					"/%02hhx%02hhx/%02hhx%02hhx",
					sa->sa_data[6],  sa->sa_data[7],
					sa->sa_data[8],  sa->sa_data[9],
					sa->sa_data[10], sa->sa_data[11],
					sa->sa_data[12], sa->sa_data[13],
					sa->sa_data[14], sa->sa_data[15],
					sa->sa_data[16], sa->sa_data[17],
					sa->sa_data[18], sa->sa_data[19],
					sa->sa_data[20], sa->sa_data[21]
					);
			break;
		default:
			out.error = "add_address_path: unknown address family";
	}
	strncat(out.value,path,buflen);
	return out;
}

static int mkdir_p(const char * path) {
	int result = 0;
	int len = strlen(path) + 2;
	char *dir = malloc(len);
	char *pathc = strdup(path);
	char *token;
	struct stat buffer = {};

	*dir = 0;
	token = strtok(pathc,"/");
	do {
		strcat(dir,token);
		if (stat(dir,&buffer)) {
			result = mkdir(dir,0777);
			if (result) {
				perror("mkdir_p");
				break;
			}
		}
		strcat(dir,"/");
	} while (token = strtok(NULL,"/"));
	if (dir) free(dir);
	if (pathc) free(pathc);
	return result;
} // mkdir_p()

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
	string_err_s path = add_address_path(ds, sa, ps.path, MAX_DS_PEER_PATH);
	if (path.error) {
		fprintf(stderr, "ds_init_peer: %s\n", path.error);
		ps.error = path.error;
	}
	else if (mkdir_p(ps.path)) {
		ps.error = strerror(errno);
		fprintf(stderr, "ds_init_peer: mkdir %s: %s\n", ps.path, ps.error);
	}
	return ps;
} // ds_init_peer_ip()

char * ds_fname_peer(const datastore_s ds, peer_s peer, char *namebuf, size_t buflen, const char * fname) {
	strncpy(namebuf, peer.path, buflen);
	strncat(namebuf, "/", buflen - strlen(namebuf));
	strncat(namebuf, fname, buflen - strlen(namebuf));
	return namebuf;
} // ds_fname_peer()

char * ds_fname_sa(const datastore_s ds, struct sockaddr * sa, char * namebuf, size_t buflen, const char *fname) {
	string_err_s path = add_address_path(ds, sa, namebuf, buflen - strlen(namebuf));
	if (path.error) {
		fprintf(stderr, "ds_peer_fname: %s\n", path.error);
		return NULL;
	}
	struct stat sbuf = {};
	if (stat(namebuf,&sbuf)) {
		fprintf(stderr,"ds_peer_fname: can't stat %s\n", namebuf);
		return NULL;
	}
	if ((sbuf.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr,"ds_peer_fname: %s is not a directory\n", namebuf);
		return NULL;
	}
	strncat(namebuf,"/",buflen - strlen(path.value));
	strncat(namebuf,fname,buflen - strlen(path.value));
	return path.value;
} // ds_fname_sa()
