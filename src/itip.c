/** \file it-interpreter.c
 * \brief main program for IPsec interpreter
 */
/*
 Copyright (C) 2017 Mathias Weidner <mathias@mamawe.net>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "ipsec.h"
#include "sockets.h"

/**
 * \brief configuration options
 */
typedef struct options_s {
	char const * cfgfile;
	char const * device;
	char const * peer;
	char const * command;
	char const * error;
} options_s;

/**
 * \brief read the command line options
 * \param argc number of arguments from main()
 * \param argv argument vector from main()
 * \return configuration options
 */
options_s get_options(int argc, char **argv) {
	int c;
	options_s opt = { };

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "config", required_argument, 0, 0 },
			{ "device", required_argument, 0, 0 },
			{ "peer",   required_argument, 0, 0 },
			{ 0,        0,                 0, 0 }
		};
		c = getopt_long(argc, argv, "c:d:p:",
				long_options, &option_index);
		if (-1 == c) 
			break;
		switch (c) {
			case 0:
				switch (option_index) {
					case 0:
						if (optarg)
							opt.cfgfile = optarg;
						break;
					case 1:
						if (optarg)
							opt.peer = optarg;
						break;
				}
				break;
			case 'c':
				opt.cfgfile = optarg;
				break;
			case 'd':
				opt.device = optarg;
				break;
			case 'p':
				opt.peer = optarg;
				break;
			default:
				opt.error = "unrecognized option";
				return opt;
		}
	}
	return opt;
} // get_options()

void sig_usr1_handler(int signal) {
	sad_dump_records((void (*)(const char *))puts);
} // sig_usr1_handler()

int main(int argc, char **argv) {
	ipsec_s is = {};

	options_s opt = get_options(argc, argv);
	if (opt.error) {
		fprintf(stderr,"error: %s\n", opt.error);
		return 1;
	}
	if (zlog_init(ITIP_ZLOG_CONF)) {
		fprintf(stderr,"error: could not initialize zlog from '%s'\n", ITIP_ZLOG_CONF);
		return 1;
	}
	signal(SIGUSR1,sig_usr1_handler);
	socket_listen(opt.device, (socket_cb_handler)ipsec_handle_datagram, &is);
	zlog_fini();
	return 0;
} // main()

