#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_ip_handler.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_icmp_handler.h"


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
uint8_t* gen_icmp_hdr (int type, int code) {

	printf("in gen icmp_pkt function===================================================");

	uint8_t *icmp_pkt = malloc(sizeof(sr_icmp_hdr_t) + sizeof(uint8_t) * ICMP_DATA_SIZE);
	/* pad icmp cargo with 0's */
	print_hdr_icmp(icmp_pkt);
	
	printf("pad cargo\n");
	bzero(icmp_pkt + sizeof(sr_icmp_t3_hdr_t), ICMP_DATA_SIZE);
	
	print_hdr_icmp(icmp_pkt);
	switch (type) {
		case 0: {
			/* ICMP type: echo reply*/
			sr_icmp_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 0;
		    icmp_hdr->icmp_code = 0;
		    icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			uint8_t *icmp_pkt = malloc(sizeof(uint8_t) * sizeof(sr_icmp_hdr_t));
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
			uint8_t *icmp_pkt = malloc(sizeof(uint8_t) * sizeof(sr_icmp_hdr_t));
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
			uint8_t *icmp_pkt = malloc(sizeof(uint8_t) * sizeof(sr_icmp_hdr_t));
			icmp_pkt = (uint8_t *)icmp_hdr;
			break;
		}
		case 3: {
			/* ICMP type 3: X unreachable*/
			sr_icmp_t3_hdr_t *icmp_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));
			icmp_hdr->icmp_type = 3;
			icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_t3_hdr_t), ICMP_DATA_SIZE);
			icmp_hdr->next_mtu = htons(512);
			uint8_t *icmp_pkt = malloc(sizeof(uint8_t) * sizeof(sr_icmp_hdr_t));

			switch (code) {				
				case 0:
					/* destination unreachable*/
					icmp_hdr->icmp_code = 0;
					icmp_pkt = (uint8_t *)icmp_hdr;
				case 1:
					/* host unreachable*/
					icmp_hdr->icmp_code = 1;
					icmp_pkt = (uint8_t *)icmp_hdr;
				case 3:
					/* port unreachable*/
					icmp_hdr->icmp_code = 3;
					icmp_pkt = (uint8_t *)icmp_hdr;
				default:
					fprintf(stderr, "unsupported ICMP code specified.\n");
					icmp_pkt = 0;
			
			} /* end of inner switch switch*/
			break;
		}
		default:
			/* ICMP type: unsupported*/
			fprintf(stderr, "unsupported ICMP type\n");
			icmp_pkt = 0;

	} /* end of outer switch statement*/

	return icmp_pkt;
}


/* Return an ethernet frame that encapsulates the ICMP packet.
 * The ICMP packet is encapsulated in an IP packet then ethernet frame.
 */
uint8_t* gen_eth_frame (uint8_t* packet, uint8_t *icmp_pkt, struct sr_if* interface) {
	printf("in gen_eth_frame\n------------------\n");
	/* Create the ethernet header*/
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)packet;

	memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	
	eth_hdr->ether_type = htons(ethertype_ip);

	/* Create the IP header*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	
	ip_hdr->ip_hl = ip_hdr->ip_hl * 4;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;				
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = ip_protocol_icmp;	

	/*print_hdr_ip((uint8_t*)ip_hdr);*/
	/* Set the source and destination IP's depending on the ICMP code and type*/

	
	sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) icmp_pkt;
/*	print_hdr_icmp(icmp_pkt);*/

	uint8_t icmp_type = icmp_hdr->icmp_type;
	uint8_t icmp_code = icmp_hdr->icmp_code;

/*	print_hdr_icmp((uint8_t)icmp_hdr);*/

	if (icmp_type == 0 && icmp_code == 0) {         /* ICMP ECHO REPLY*/
			uint32_t dst = ip_hdr->ip_dst;			/* swap the src and dst ip's*/
			ip_hdr->ip_dst = ip_hdr->ip_src;
			ip_hdr->ip_src = dst;
	}
	else if (icmp_type == 3) {						/* ICMP PORT UNREACHABLE*/
		if (icmp_code == 3) {
			ip_hdr->ip_src = interface->ip;	
		} else {									/* ICMP NET/HOST UNREACHABLE*/
			ip_hdr->ip_src = ip_hdr->ip_dst;
		}
		ip_hdr->ip_dst = ip_hdr->ip_src;
	} else if (icmp_type == 11 && icmp_code == 0) {		/* ICMP TIME EXCEEDED */
		ip_hdr->ip_src = interface->ip;
		ip_hdr->ip_dst = ip_hdr->ip_src;
	}
	
	printf("compute ICMP checksum\n");
	/* compute the expected ICMP packet's checksum and ethernet frame size*/
	int len = 0;
	ip_hdr->ip_sum = 0;
	if (icmp_type != 3) {
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_ip_hdr_t), ip_hdr->ip_len);
/*		fprintf(stdout, "ICMP header \n");
		print_hdrs(icmp_pkt, sizeof(sr_icmp_t3_hdr_t));
*/
		len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	} else {
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_ip_hdr_t), ip_hdr->ip_len);
/*		fprintf(stdout, "ICMP header \n");
		print_hdrs(icmp_pkt, sizeof(sr_icmp_hdr_t));
*/
		len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	}
	
	/* Encapsulate the three protocol packets into one*/
	uint8_t *new_eth_pkt = malloc(len);
	uint8_t *eth_cargo = new_eth_pkt + sizeof(sr_ethernet_hdr_t);
	uint8_t *ip_cargo = eth_cargo + sizeof(sr_ip_hdr_t);
	
	memcpy(new_eth_pkt, eth_hdr, sizeof(sr_ethernet_hdr_t));
	memcpy(eth_cargo, ip_hdr, sizeof(sr_ip_hdr_t));
	memcpy(ip_cargo, icmp_pkt, sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE);
/*
	printf("printing out the ethernet packets");
	print_hdr_eth(new_eth_pkt);
	print_hdr_ip(eth_cargo);
	print_hdr_icmp(ip_cargo);*/
	return new_eth_pkt;
}



void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(0, 0), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}

void send_icmp_echo_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(8, 0), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}


void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(3, 0), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}


void send_icmp_host_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(3, 1), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}


void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(3, 3), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}


void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface) {
	uint8_t *eth_pkt = gen_eth_frame(packet, gen_icmp_hdr(11, 0), interface);
	int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(eth_pkt + sizeof(sr_ethernet_hdr_t));
	cached_send(sr, eth_pkt, len, lpm(sr->routing_table, ip_hdr->ip_dst));
	free(eth_pkt);
}