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
		printf("	Got an ARP packet!===============\n");
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

		if (!sr_get_if_from_ip(arp_hdr->ar_tip, sr->if_list)) {
			fprintf(stderr, "ERROR: This ARP packet is not for us\n");
			return;
		}

		if (arp_hdr->ar_op == htons(arp_op_request)) {
			printf("	got an arp op_request\n");
			respond_to_arpreq(sr, packet, len, inf);
		}
		else if (arp_hdr->ar_op == htons(arp_op_reply)) {
			printf("	got an op_reply\n");

			struct sr_arpreq *req_entry = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
			printf("	Loop through list of recent packets that replied to us and send arp reply for each...\n");
			
			struct sr_packet *current_packet = req_entry->packets;
			while (current_packet) {
				printf("		Constructing arp request packet..\n");
				uint8_t *reply_pkt = current_packet->buf;
				sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) reply_pkt;
				struct sr_if *if_out = sr_get_interface(sr, current_packet->iface);
				memcpy(eth_hdr->ether_shost, if_out->addr, ETHER_ADDR_LEN);
				memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				
				printf("		sending arp request packet...\n");
				sr_send_packet(sr, reply_pkt, current_packet->len, current_packet->iface);
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
		handle_IP(sr, packet, len, interface);
		
	} /*end of handling ethertype_ip packet */
	else {
		fprintf(stderr, "Got an invalid packet type(not IP or ARP)...\n");
	}
} /* end of sr_packet handling*/



/**
 * handle ARP type packets. 
 * 
 * @param sr        sr instance
 * @param packet    incoming ARP packet sent
 * @param len       length of this packet
 * @param interface interface this packet as sent through
 */
void handle_ARP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* iface) {
	printf("In handle_ARP()------------------------------\n");
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	if (!sr_get_if_from_ip(arp_hdr->ar_tip, sr->if_list)) {
		fprintf(stderr, "ERROR: ARP packet not for us.\n");
		return;
	}

	if (arp_hdr->ar_op == htons(arp_op_request)) {
		printf("	got an op_request\n");
		respond_to_arpreq(sr, packet, len, iface);
	}
	else if (arp_hdr->ar_op == htons(arp_op_reply)) {
		printf("	got an op_reply\n");
		
		struct sr_arpreq *req_entry = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

		/*loop through list of waiting packets that replied to us and 
		and send an arp request to each.*/	
		struct sr_packet *current_packet = req_entry->packets;
		while (current_packet) {
			/* construct arp request packet*/
			printf("	Send arp request\n");
			uint8_t *request_pkt = current_packet->buf;
			sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) request_pkt;
			struct sr_if *out_iface = sr_get_interface(sr, current_packet->iface);
			memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			
			/*actually send packet through outgoing interface*/
			sr_send_packet(sr, request_pkt, current_packet->len, current_packet->iface);
			current_packet = current_packet->next;
		}
		sr_arpreq_destroy(&(sr->cache), req_entry);
	}
	else {
		fprintf(stderr, "ERROR: invalid ARP type specified\n");
	}
}