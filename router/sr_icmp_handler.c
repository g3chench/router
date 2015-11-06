#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_icmp_handler.h"


size_t eth_frame_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE;
/*
const uint8_t MIN_ETH_SIZE = 64*sizeof(uint8_t);
const uint8_t MAX_ETH_SIZE = 1500*sizeof(uint8_t);
*/
/*
* Return a newly constructed ICMP packet struct given the type, code 
  and length of data the packet holds and the pointer to that data 
  as well.

*/

/* FIX/CHECK from the assignment
You may want to create additional structs for ICMP messages for
 convenience, but make sure to use the packed attribute so that
  the compiler doesn’t try to align the fields in the struct to 
  word boundaries:
*/


/*
 * Return an ICMP packet header given its type and code. 
 */
uint8_t* gen_icmp_packet (int type, int code) {
	uint8_t *icmp_pkt = malloc(sizeof(sr_icmp_hdr_t) + sizeof(uint8_t) * ICMP_DATA_SIZE);
	/* pad icmp cargo with 0's */
	bzero(icmp_pkt + sizeof(sr_icmp_t3_hdr_t), ICMP_DATA_SIZE);
	
	switch (type) {
		case 0: {
			/* ICMP type: echo reply*/
			sr_icmp_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 0;
		    icmp_hdr->icmp_code = 0;
		    icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			icmp_pkt = (uint8_t *)icmp_hdr;
			break;
		}
		case 8: {
			/* ICMP type: echo request*/
			sr_icmp_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 8;
		    icmp_hdr->icmp_code = 0;
		    icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			icmp_pkt = (uint8_t *)icmp_hdr;
			break;
		}
		case 11: {
			/* ICMP type: time exceeded*/
			sr_icmp_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 11;
		    icmp_hdr->icmp_code = 0;
		    icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			icmp_pkt = (uint8_t *)icmp_hdr;
			break;
		}
		case 3: {
			/* ICMP type 3: X unreachable*/
			sr_icmp_t3_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));
			icmp_hdr->icmp_type = 3;
			icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_t3_hdr_t), ICMP_DATA_SIZE);
			icmp_pkt = (uint8_t *)icmp_hdr;
			icmp_hdr->next_mtu = htons(512);

			switch (code) {				
				case 0:
					/* destination unreachable*/
					icmp_hdr->icmp_code = 0;

				case 1:
					/* host unreachable*/
					icmp_hdr->icmp_code = 1;

				case 3:
					/* port unreachable*/
					icmp_hdr->icmp_code = 3;

				default:
					fprintf(stderr, "unsupported ICMP code specified.\n");
					icmp_pkt = NULL;
			
			} /* end of inner switch switch*/
			break;
		}
		default:
			/* ICMP type: unsupported*/
			fprintf(stderr, "unsupported ICMP type\n");
			icmp_pkt = NULL;

	} /* end of outer switch statement*/

	return icmp_pkt;
}


/* Return an ethernet frame that encapsulates the ICMP packet.
 * The ICMP packet is encapsulated in an IP packet then ethernet frame.
 */


     /* REMOVE THIS COMMENT
                Ethernet frame
      ------------------------------------------------
      | Ethernet hdr |       IP Packet               |
      ------------------------------------------------
                     ---------------------------------
                     |  IP hdr |   IP Packet         |
                     ---------------------------------
                      		   -----------------------
                      		   |ICMP hdr | ICMP DATA |
                      		   -----------------------
    */

uint8_t* gen_eth_frame (uint8_t* packet, uint8_t *icmp_pkt, int icmp_type, int icmp_code, struct sr_if* interface) {

	/* Create the ethernet header*/
	sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(eth_hdr));

	sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)packet;
	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ethertype_ip);

	/* Create the IP header*/
	sr_ip_hdr_t *ip_hdr = malloc(sizeof(sr_ip_hdr_t));
	ip_hdr->ip_hl = ip_hdr->ip_hl * 4;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;				
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = ip_protocol_icmp;	

	/* Set the source and destination IP's depending on the ICMP code and type*/
	if (icmp_type == 0 && icmp_code == 0) {
		if (icmp_code == 0) { 						/* ICMP ECHO REPLY*/
			uint32_t dst = ip_hdr->ip_dst;			/* swap the src and dst ip's*/
			ip_hdr->ip_dst = ip_hdr->ip_src;
			ip_hdr->ip_src = dst;
		}
	}
	else if (icmp_type == 3) {						/* ICMP PORT UNREACHABLE*/
		if (icmp_code == 3) {						/* ICMP NET/HOST UNREACHABLE*/
			ip_hdr->ip_src = interface->ip;	
		} else {
			ip_hdr->ip_src = ip_hdr->ip_dst;
		}
		ip_hdr->ip_dst = ip_hdr->ip_src;
	} else if (icmp_type == 11 && icmp_code == 0) {		/* ICMP TIME EXCEEDED */
		ip_hdr->ip_src = interface->ip;
		ip_hdr->ip_dst = ip_hdr->ip_src;
	}
	
	/* compute the expected ICMP packet's checksum*/
	ip_hdr->ip_sum = 0;
	if (icmp_type != 3) {
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_icmp_hdr_t), ip_hdr->ip_len);
/*		fprintf(stdout, "ICMP header \n");
		print_hdrs(icmp_pkt, sizeof(sr_icmp_t3_hdr_t));
*/
	} else {
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_icmp_t3_hdr_t), ip_hdr->ip_len);
/*		fprintf(stdout, "ICMP header \n");
		print_hdrs(icmp_pkt, sizeof(sr_icmp_hdr_t));
*/
	}
	
	/* Encapsulate the three protocol packets into one*/
	uint8_t *new_eth_pkt = malloc(eth_frame_size);
	uint8_t *eth_cargo = new_eth_pkt + sizeof(sr_ethernet_hdr_t);
	uint8_t *ip_cargo = eth_cargo + sizeof(sr_ip_hdr_t);
	
	memcpy(new_eth_pkt, eth_hdr, sizeof(sr_ethernet_hdr_t));
	memcpy(eth_cargo, ip_hdr, sizeof(sr_ip_hdr_t));
	memcpy(ip_cargo, icmp_pkt, sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE);
/*
	fprintf(stdout, "Ethernet header\n");
	print_hdr_eth(new_eth_pkt);
	fprintf(stdout, "IP header\n");
	print_hdr_ip(eth_cargo);
	fprintf(stdout, "ICMP header\n");
	print_hdr_icmp(ip_cargo);
*/	

	return (uint8_t*) new_eth_pkt;
}

	
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(0, 0), 0, 0, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}

void send_icmp_echo_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(8, 0), 8, 0, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}


void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(3, 0), 3, 0, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}


void send_icmp_host_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(3, 1), 3, 0, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}


void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(3, 3), 3, 3, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}


void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_packet(11, 0), 11, 0, interface);
	int result = sr_send_packet(sr, eth_pkt, eth_frame_size, (const char* ) interface);
	free(eth_pkt);
}
