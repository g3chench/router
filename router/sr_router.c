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
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
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

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	/* fill in code here */

	struct sr_if *new_inf = sr_get_interface(sr, interface);
	
	/*NEEDS TO BE CHECKED AGAIN*/
	sr_ethernet_hdr_t *eth_hdr = (struct sr_ethernet_hdr *)packet;
	/*
	sr_ethernet_hdr *eth_hdr = (sr_ethernet_hdr *)
	*/

	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	switch(ether_type){
		case ethertype_arp:
			printf("DEBUG: ARP PACKET RECEIVED.\n");
			sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (sizeof(sr_ethernet_hdr_t) + packet);
			enum sr_arp_opcode arp_op_type = arp_hdr->ar_op;

			if (sr_get_if_from_ip(arp_hdr->ar_tip, sr->if_list) == NULL) {
				printf("ERROR: Invalid ARP Packet.\n");
				return;
			}

			if (arp_op_type == htons(arp_op_request)) {
				uint8_t *pkt_resp = malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));

				struct sr_ethernet_hdr *eth_hdr_resp = (struct sr_ethernet_hdr *)pkt_resp;
				struct sr_ethernet_hdr *eth_hdr_reply = (struct sr_ethernet_hdr *)packet;
				enum sr_ethertype eth_arp = ethertype_arp;
				enum sr_ethertype eth_ip = ethertype_ip;
				memcpy(eth_hdr_resp->ether_dhost, eth_hdr_reply->ether_shost, ETHER_ADDR_LEN);
				memcpy(eth_hdr_resp->ether_shost, new_inf->addr, ETHER_ADDR_LEN);
				eth_hdr_resp->ether_type = htons(eth_arp);
				
				struct sr_arp_hdr *arp_hdr_resp = ((struct sr_arp_hdr *)(sizeof(sr_ethernet_hdr_t) + pkt_resp));
				struct sr_arp_hdr *arp_hdr_reply = ((struct sr_arp_hdr *)(sizeof(sr_ethernet_hdr_t) + packet));
				enum sr_arp_hrd_fmt hdr_arp = arp_hrd_ethernet;
				enum sr_arp_opcode opcode = arp_op_reply;


				arp_hdr_resp->ar_hrd = htons(hdr_arp);
				arp_hdr_resp->ar_pro = htons(eth_ip);
				arp_hdr_resp->ar_hln = ETHER_ADDR_LEN;
				arp_hdr_resp->ar_pln = 4;
				arp_hdr_resp->ar_op = htons(opcode);
				arp_hdr_resp->ar_sip = new_inf->ip;
				arp_hdr_resp->ar_tip = arp_hdr_reply->ar_sip;
				memcpy(arp_hdr_resp->ar_sha, new_inf->addr, ETHER_ADDR_LEN);
				memcpy(arp_hdr_resp->ar_tha, arp_hdr_reply->ar_sha, ETHER_ADDR_LEN);				 	


				/* Send a reply */
				sr_send_packet(sr, pkt_resp, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), new_inf->name);

				/* Free after Packet is Sent */
				free(pkt_resp);
			}
			else if (arp_op_type == htons(arp_op_reply)) {
				printf("DEBUG: INCOMING ARP REPLY PACKET\n");

				struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

				struct sr_packet *curr_pkt = arpreq->packets;
				while (curr_pkt != NULL) {
					uint8_t *curr_frame = curr_pkt->buf;
					struct sr_packet *next_pkt = curr_pkt->next;
					struct sr_if *interface = sr_get_interface(sr, curr_pkt->iface);
					sr_ethernet_hdr_t *eth_hdr_f = (sr_ethernet_hdr_t *) curr_frame;
					memcpy(eth_hdr_f->ether_shost, interface->addr, ETHER_ADDR_LEN);
					memcpy(eth_hdr_f->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
					printf("1.. DEBUG: SEND_PACKET.\n");
					sr_send_packet(sr, curr_frame, curr_pkt->len, curr_pkt->iface);
					curr_pkt = next_pkt;
				}
				sr_arpreq_destroy(&(sr->cache), arpreq);
			}
			else {
				printf("ERROR: Invalid Operation Type.\n");
			}
			break;

		case ethertype_ip:
			printf("DEBUG: INCOMING IP PACKET.\n");
			/* Jump past ethernet header to point at IP header */
			struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

			/* Sancheck: minimum length and correct checksum. */
			uint16_t packet_cksum = ip_hdr->ip_sum;
			ip_hdr->ip_sum = 0;
			int ip_hl = ip_hdr->ip_hl * 4;
			uint16_t calculated_cksum = cksum(ip_hdr, ip_hl);
			unsigned int min_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
			if (calculated_cksum != packet_cksum || len < min_packet_len) {
				printf("ERROR: incoming packet is malformed (checksum mismatch or packet length too short.\n");
				return;
			}
			ip_hdr->ip_sum = packet_cksum; /* Restore checksum */
			/* IP packet is destined for one of our interfaces */
			if (sr_get_if_from_ip(ip_hdr->ip_dst, sr->if_list)) {
				printf("DEBUG: INCOMING IP PACKET IS DESTINED FOR ONE OF OUR INTERFACES\n");
				uint8_t ip_protocol = ip_hdr->ip_p;
					if (ip_protocol == ip_protocol_icmp)
					{
						sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
						/*printf("DEBUG: ICMP TYPE: %d\n", icmp_hdr->icmp_type);
						printf("DEBUG: ICMP TYPE + htons: %d\n", htons(icmp_hdr->icmp_type));
						printf("DEBUG: ICMP CODE: %d\n", icmp_hdr->icmp_code);
						printf("DEBUG: ICMP CODE + htons: %d\n", htons(icmp_hdr->icmp_code));*/
						if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) { /* ICMP echo request */
							printf("DEBUG: RECIEVED ICMP ECHO REQUEST\n");
							/* Sancheck: checksum */
							uint16_t packet_cksum_icmp = icmp_hdr->icmp_sum;
							icmp_hdr->icmp_sum = 0;
							uint16_t calculated_checksum_icmp = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
							/*printf("PACKET CHECKSUM: %d\n", packet_cksum);
							printf("PACKET CHECKSUM (htons): %d\n", htons(packet_cksum));
							printf("CALCULATED CHECKSUM: %d\n", calculated_checksum);
							printf("CALCULATED CHECKSUM (htons): %d\n", htons(calculated_checksum));*/
							if (packet_cksum_icmp == calculated_checksum_icmp) {
								icmp_hdr->icmp_sum = packet_cksum_icmp; /* Restore checksum */
								handle_ICMP(sr, ICMP_ECHOREPLY, packet, len, 0);
							}
							else {
								printf("ERROR: checksum mismatch on incoming ICMP echo request packet.\n");
							}
						}
					}
					else if (ip_protocol == ip_protocol_udp || ip_protocol == ip_protocol_tcp) {
						handle_ICMP(sr, ICMP_PORTUNREACHABLE, packet, 0, 0);
					}
					else { /* ignore packet */
						printf("ERROR: Unsupported IP protocol type.\n");
					}
			}
			else { /* packet not for us; we forward it */
				printf("DEBUG: NEED TO FORWARD IP PACKET\n");
				forward_ip_packet(sr, packet, len);
			}
			break;
		
		default:
			printf("ERROR: Unsupported packet type. \n");
			break;
	}
}/* end sr_handlepacket */
