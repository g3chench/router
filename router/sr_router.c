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

	printf("*** -> Received packet of length %d \n",len);

	struct sr_if *new_interface = sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	switch(ether_type){

		case ethertype_arp:
			printf("DEBUG: ARP PACKET RECEIVED.\n");
			sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (sizeof(sr_ethernet_hdr_t) + packet);
			enum sr_arp_opcode arp_op_type = arp_hdr->ar_op;

			if (!sr_get_if_from_ip(arp_hdr->ar_tip, sr->if_list)) {
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
				memcpy(eth_hdr_resp->ether_shost, new_interface->addr, ETHER_ADDR_LEN);
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
				arp_hdr_resp->ar_sip = new_interface->ip;
				arp_hdr_resp->ar_tip = arp_hdr_reply->ar_sip;
				memcpy(arp_hdr_resp->ar_sha, new_interface->addr, ETHER_ADDR_LEN);
				memcpy(arp_hdr_resp->ar_tha, arp_hdr_reply->ar_sha, ETHER_ADDR_LEN);				 	


				/* Send a reply */
				sr_send_packet(sr, pkt_resp, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), new_interface->name);

				/* Free after Packet is Sent */
				free(pkt_resp);
			}
			else if (arp_op_type == htons(arp_op_reply)) {
				printf("DEBUG: INCOMING ARP REPLY PACKET\n");
				/* sr_arpcache_insert inserts the reply into the cache and return the corresponding request entry */
				struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
				/* Go through linked list of all packets waiting on the ARP request we just got a reply to,
				* fill in the MAC address in each packet's frame, and send the packet */
				struct sr_packet *curr_pkt = arpreq->packets;
				while (curr_pkt) {
					uint8_t *frame = curr_pkt->buf;
					struct sr_packet *next_pkt = curr_pkt->next;
					sr_ethernet_hdr_t *eth_hdr_f = (sr_ethernet_hdr_t *) frame;
					struct sr_if *interface_out = sr_get_interface(sr, curr_pkt->iface);
					memcpy(eth_hdr_f->ether_shost, interface_out->addr, ETHER_ADDR_LEN);
					memcpy(eth_hdr_f->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
					sr_send_packet(sr, frame, curr_pkt->len, curr_pkt->iface);
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

			struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(sizeof(sr_ethernet_hdr_t) + packet);

			uint16_t expected_cksum = ip_hdr->ip_sum;
			ip_hdr->ip_sum = 0;

			uint16_t actual_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

			if (actual_cksum != expected_cksum) {
				printf("ERROR: checksum don't match.\n");
				return;
			} else if ((sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)) > len){
				printf("ERROR: packet length too short.\n");
				return;
			} else {
				ip_hdr->ip_sum = expected_cksum; 
				if (sr_get_if_from_ip(ip_hdr->ip_dst, sr->if_list)) {
					printf("DEBUG: INCOMING IP PACKET\n");
					uint8_t protocol = ip_hdr->ip_p;

					sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(sizeof(sr_ip_hdr_t) + packet + sizeof(sr_ethernet_hdr_t));

					if (protocol == ip_protocol_icmp)
					{
						if (icmp_hdr->icmp_code == 0 && icmp_hdr->icmp_type == 8) { 
							printf("DEBUG: ICMP ECHO REQUEST RECEIVED\n");

							uint16_t expected_icmp_cksum = icmp_hdr->icmp_sum;
							icmp_hdr->icmp_sum = 0;

							uint16_t actual_icmp_checksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

							if (expected_icmp_cksum == actual_icmp_checksum) {
								icmp_hdr->icmp_sum = expected_icmp_cksum; 
								icmp_handler(sr, ICMP_ECHOREPLY, packet, len, 0);
							}
							else {
								printf("ERROR: Checksum do not match on ICMP echo request packet.\n");
							}
						}
					}
					else if (protocol == ip_protocol_udp || protocol == ip_protocol_tcp) {
						icmp_handler(sr, ICMP_PORTUNREACHABLE, packet, 0, ip_hdr->ip_dst);
					}
					else { /* ignore packet */
						printf("ERROR: Unsupported IP protocol type.\n");
					}
				}
				else { /* packet not for us; we forward it */
					printf("DEBUG: NEED TO FORWARD IP PACKET\n");

					sr_ip_hdr_t *ip_hdr_new = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

					ip_hdr_new->ip_ttl--;
					if (ip_hdr_new->ip_ttl < 1) {
						printf("TTL of packet we have to forward is 0. Sending Time Exceeded ICMP.\n");
						icmp_handler(sr, ICMP_TIMEEXCEEDED, packet, 0, 0);
						return;
					}
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = cksum(ip_hdr_new, ip_hdr_new->ip_hl * 4);

					struct sr_rt *lpm = LPM(ip_hdr_new->ip_dst, sr->routing_table);
					if (!lpm) {
						icmp_handler(sr, ICMP_NETUNREACHABLE, packet, 0, 0);
						return;
					}

					lookup_and_send(sr, packet, len, lpm);
					
				}

			}
			break;
		
		default:
			printf("ERROR: Unsupported packet type. \n");
			break;
	}

}/* end sr_handlepacket */
