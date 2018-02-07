/** \file pcapture.c
 * \brief functions regarding packet capture
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

#include <arpa/inet.h>
#include <stdlib.h>

#include "pcapture.h"

char * ipsec_filter = "udp and ( port 500 or port 4500 ) or proto 50 or proto 51";

static pcap_t * get_handle(char const *dev) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask = 0;
	pcap_t *handle;

	if (NULL == dev) {
		dev = pcap_lookupdev(errbuf);
		if (NULL == dev) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(1);
		}
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
	if (NULL == handle) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(6);
	}
	if (DLT_EN10MB != pcap_datalink(handle)) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		exit(3);
	}
	if (-1 == pcap_compile(handle, &fp, ipsec_filter, 0, mask)) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", ipsec_filter, pcap_geterr(handle));
		exit(7);
	}
	if (-1 == pcap_setfilter(handle, &fp)) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", ipsec_filter, pcap_geterr(handle));
		exit(8);
	}
	return handle;
} // get_handle()

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	char namebuf[MAX_DS_PEER_PATH];
	pcapture_user_data *ud = (pcapture_user_data *)args;
	datastore_s *ds_p = ud->ds;
	pcap_t *handle = ud->handle;
	if (ds_p) {
		const sniff_ethernet *ethernet = (sniff_ethernet *)packet;
		char printbuf[2*ETHER_ADDR_LEN+1];
		if (header->caplen < sizeof(sniff_ethernet)) {
			return; // not even an ethernet header captured
		}
		u_short et = ntohs(ethernet->ether_type);
		if (0x800 == et) {
			if (header->caplen < sizeof(sniff_ethernet) + sizeof(sniff_ip4)) {
				return; // to small for IPv4 header
			}
			sniff_ip4 * ip4 = (sniff_ip4 *)(packet + sizeof(sniff_ethernet));
			namebuf[MAX_DS_PEER_PATH];
			struct sockaddr_in sa = {.sin_family=AF_INET,.sin_addr=ip4->src};
			if (ds_fname_sa(*ds_p,(struct sockaddr *)&sa, namebuf, MAX_DS_PEER_PATH, "ipsec.pcap")) {
				pcap_dumper_t *dumper;
			        if (dumper = pcap_dump_open_append(handle, namebuf)) {
					pcap_dump((u_char *)dumper, header, packet);
					pcap_dump_close(dumper);
				}
				else {
					fprintf(stderr,"Could not dump %s: %s\n", namebuf, pcap_geterr(handle));
				}
			}
			ud->handler((u_char *)ip4,header->caplen - sizeof(sniff_ethernet), ud->ds);
		}
		else if (0x86dd == et) {
			if (header->caplen < sizeof(sniff_ethernet) + sizeof(sniff_ip6)) {
				return; // to small for IPv6 header
			}
			sniff_ip6 * ip6 = (sniff_ip6 *)(packet + sizeof(sniff_ethernet));
			// TODO: dump IPv6 packet
		}
		else {
			return; // neither IPv4 nor IPv6
		}
		//char * fname ds_peer_fname(*ds_p, struct sockaddr *, namebuf, MAX_DS_PEER_PATH, "ipsec.pcap");
		return;
	}
} // got_packet()

/**
 * \brief capture loop for IPsec interpreter
 * \param dev name of network interface for IPsec
 * \param ds DS handle
 * \param ih callback function for captured packets
 * \return return value from pcap_loop()
 */
int pcapture(char const *dev, datastore_s ds, ipsec_handler ih) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	bpf_u_int32 mask = 0;
	int result;

	handle = get_handle(dev);
	pcapture_user_data ud = {.ds=&ds, .handle=handle, .handler=ih};
	result = pcap_loop(handle, -1, got_packet, (u_char *)&ud);
	return result;
} // pcapture()

/**
 * \brief create a PCAP file to dump the captured packets into
 * \param dev name of network interface
 * \param fname file name for the PCAP file
 * \return ???
 */
int pcapture_create_file(char const *dev, char const *fname) {
	pcap_t *handle;
	pcap_dumper_t *dumper;

	handle = get_handle(dev);
	dumper = pcap_dump_open(handle, fname);
	if (NULL == dumper) {
		fprintf(stderr, "Couldn't open dump file %s: %s\n", fname, pcap_geterr(handle));
		exit(9);
	}
	pcap_dump_close(dumper);
	pcap_close(handle);
} // pcapture_create_file()

// end of pcapture.c
