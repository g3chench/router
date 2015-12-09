/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_router.h" 
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) {
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) 
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	/* fill in code here */
	printf("IN sr_router.c: sr_handlepacket\n");
	struct sr_if *inf = sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	if (ether_type == ethertype_arp) {
		printf("Got an ARP packet!===============\n");
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

		if (!sr_get_if_from_ip(arp_hdr->ar_tip, sr->if_list)) {
			fprintf(stderr, "ERROR: ARP packet not for us.\n");
			return;
		}

		if (arp_hdr->ar_op == htons(arp_op_request)) {
			printf("Received ARP_OP_REQUEST\n");
			respond_to_arpreq(sr, packet, len, inf);
		}
		else if (arp_hdr->ar_op == htons(arp_op_reply)) {
			printf("Received ARP_OP_REPLY\n");
			/* sr_arpcache_insert inserts the reply into the cache and return the corresponding request entry */
			struct sr_arpreq *req_entry = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
			/* Go through linked list of all packets waiting on the ARP request we just got a reply to,
			* fill in the MAC address in each packet's frame, and send the packet */
			struct sr_packet *current_packet = req_entry->packets;
			while (current_packet) {
				uint8_t *raw_frame = current_packet->buf;
				sr_ethernet_hdr_t *frame_eth_hdr = (sr_ethernet_hdr_t *) raw_frame;
				struct sr_if *if_out = sr_get_interface(sr, current_packet->iface);
				memcpy(frame_eth_hdr->ether_shost, if_out->addr, ETHER_ADDR_LEN);
				memcpy(frame_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				printf("Sending arp request\n");
				/*print_hdrs(raw_frame, current_packet->len);*/
				sr_send_packet(sr, raw_frame, current_packet->len, current_packet->iface);
				current_packet = current_packet->next;
			}
			sr_arpreq_destroy(&(sr->cache), req_entry);
		}
		else {
			fprintf(stderr, "ERROR: invalid ARP type specified\n");
		}
	}
	else if (ether_type == ethertype_ip) {
		printf("Got an ETHERNET packet===========\n");
		struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

		printf("Perform packet sanity checks...\n");
		uint16_t expected_cksum = ip_hdr->ip_sum;
		ip_hdr->ip_sum = 0;
		uint16_t actual_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
		
		/* Perform sanity checks */
		unsigned int min_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
		if (len < min_packet_len) {
			fprintf(stderr, "ERROR: Invalid packet length.\n");
			return;
		}

		if (actual_cksum != expected_cksum) {
			fprintf(stderr, "ERROR: checksum mismatch.\n");
			return;
		}
		ip_hdr->ip_sum = expected_cksum;
		/*printf("Passed sanity checks!\n");*/

		
		if (sr_get_if_from_ip(ip_hdr->ip_dst, sr->if_list)) {
			printf("Got an IP packet for us!\n");

			if (ip_hdr->ip_p == ip_protocol_icmp) {
				sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
				printf("icmp type, code: %d, %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);	
				
				if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {				/* handle icmp echo request */
					printf("Got an ICMP ECHO REQUEST!\n");
					/* Sancheck: checksum */
					uint16_t icmp_expected_cksum = icmp_hdr->icmp_sum;
					icmp_hdr->icmp_sum = 0;
					uint16_t icmp_computed_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
					
					if (icmp_expected_cksum == icmp_computed_cksum) {
						icmp_hdr->icmp_sum = icmp_expected_cksum; /* Restore checksum */
						printf("sending ICMP ECO REPLY...\n");
						handle_ICMP(sr, ECHO_REPLY, packet, len, 0);
					}
					else {
						fprintf(stderr, "ERROR: mismatching ICMP checksums\n");
					}
				}
			}
			else if (ip_hdr->ip_p == ip_protocol_udp || ip_hdr->ip_p == ip_protocol_tcp) {
				handle_ICMP(sr, PORT_UNREACHABLE, packet, 0, 0);

			} else { /* ignore packet */
				fprintf(stderr, "ERROR: Unsupported IP protocol type.\n");
			}
		} else {
			fprintf(stderr, "This packet isn't for us. Forward it to the next router!\n");
			forward_ip_packet(sr, packet, len);
		}
	} /*end of handling ethertype_ip packet */
	else {
		printf("Recieved invalid packet type\n");
	}
} /* end of sr_packet handling*/