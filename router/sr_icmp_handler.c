#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_icmp_handler.h"

// CHECK/FIX do we have to pad the ICMP cargo with 0s if there is no
			// data stored in the ICMP packet?


/*
* Return a newly constructed ICMP packet struct given the type, code 
  and length of data the packet holds and the pointer to that data 
  as well.

*/

/* FIX/CHECK from the assignment
WTF DOES THIS FRIGGEN MEAN???????????????????????*/
/*
You may want to create additional structs for ICMP messages for
 convenience, but make sure to use the packed attribute so that
  the compiler doesn’t try to align the fields in the struct to 
  word boundaries:

*/  
uint8_t* gen_icmp_packet (uint8_t *packet, int type, int code=0) {
	uint8_t* packet; 
	switch (type) {


		case 0:
			/* echo reply*/
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 0;
		    icmp_hdr->icmp_code = 0;
			
		    // REMOVE THIS NOTE:
		    // uint16_t cksum(const void *_data, int len);
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			packet = icmp_hdr;
		

		case 11:
			/* time exceeded */
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t));
			icmp_hdr->icmp_type = 11;
		    icmp_hdr->icmp_code = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(sr_icmp_hdr_t), ICMP_DATA_SIZE);
			packet = icmp_hdr;
		

		case 3:
			sr_icmp_t3_hdr_t icmp_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));
			icmp_hdr->type = 3;
			icmp_hdr->icmp_sum = cksum(icmp_hdr + sizeof(icmp_hdr), ICMP_DATA_SIZE);

			switch (code) {
				/* destination unreachable*/
				case 0:
					icmp_hdr->icmp_code = 0;

				/* host unreachable*/
				case 1:
					icmp_hdr->icmp_code = 1;

				/* port unreachable*/
				case 3:
					icmp_hdr->icmp_code = 3;

				/* invalid icmp type to use*/
				// FIX/CHECK but it defaults to 0 anyways..
				default:
					fprintf("unsupported ICMP code specified.\n");
					packet = NULL;
			}

			packet = icmp_hdr;

		default:
			/* unsupported icmp type*/
			fprintf("unsupported ICMP type\n");
			packet = NULL;
	}

	return packet;
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

sr_ethernet_hdr_t* gen_eth_frame (sr_ethernet_hdr_t *old_eth_pkt, old_len, uint8_t *icmp_pkt, int icmp_type) {

	/* Create the ethernet header */	
	////////////////////////////////////////////////////////
	///// FIX/CHECK: THIS POINTER ARITHMETIC //////////////////////
	////////////////////////////////////////////////////////

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	
	/* update the source and destination addresses in the new ethernet frame to forward */
	memcpy(eth_hdr->ether_dhost, ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, ether_dhost, ETHER_ADDR_LEN);
	
	// REMOVE THIS COMMMENT: ether_type_ip from line 157 of sr_protocol.h
	eth_hdr->ether_type = htons(ether_type_ip);


	/* Create the IP header*/
	sr_ip_hdr_t *ip_hdr = malloc(sizeof(sr_ip_hdr_t));
	////////////////////////////////////////////////////////
	///// FIX/CHECK: ip_hdr->tos val //////////////////////
	////////////////////////////////////////////////////////
	ip_hdr->ip_tos = 0;				
	ip_hdr->ip_len = (size_t)(sizeof(sr_ip_hdr_t));
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons();
	ip_hdr->ip_p = 1;]
	memcpy(ip_hdr->ip_src, ether_dhost, ETHER_ADDR_LEN);
	memcpy(ip_hdr->ip_dst, ether_shost, ETHER_ADDR_LEN);

	/* NOTE: Assume that a valid icmp code is given? cuz we do the check in 
	gen_icmp_pkt*/
	if (icmp_type == 3) {
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_ip_hdr_t) , sizeof(sr_icmp_t3_hdr_t) + ICMP_DATA_SIZE);
	} else { // type == 0
		ip_hdr->ip_sum = cksum(ip_hdr + sizeof(sr_ip_hdr_t) , sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE);
	}


	/* package the three protocol packets into one*/
	uint8_t *new_eth_pkt = malloc((uint8_t)(sizeof(sr_ethernet_hdr_t) ));
	uint8_t *eth_cargo = new_eth_pkt + sizeof(sr_ethernet_hdr_t);
	uint8_t *ip_cargo = eth_cargo + sizeof(sr_ip_hdr_t);
	
	memcpy(new_eth_pkt, eth_hdr, sizeof(sr_ethernet_hdr_t));
	memcpy(eth_cargo, ip_hdr, sizeof(sr_ip_hdr_t));
	memcpy(ip_cargo, icmp_pkt, sizeof(sr_icmp_hdr_t));

	return new_eth_pkt;
}



// a global variable that should prolly be at the top of this class
size_t eth_frame_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE;
	
void send_icmp_echo_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_send_packet(sr, gen_icmp_packet(packet, 0), eth_frame_size, interface);
}


void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_send_packet(sr, gen_icmp_packet(packet, 3, 0), eth_frame_size, interface);
}


void send_icmp_host_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_send_packet(sr, gen_icmp_packet(packet, 3, 1), eth_frame_size, interface);
}


void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_send_packet(sr, gen_icmp_packet(packet, 3, 3), eth_frame_size, interface);
}


void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
	sr_send_packet(sr, gen_icmp_packet(packet, 11), eth_frame_size, interface);
}




/////////////////////Chris this is your code right??? gunna leave it
	// here
/* Send icmp host unreachable to source addr of all pkts waiting on this request */
/*
void send_icmp_unreachable(struct sr_instance *sr, struct sr_arpreq *req) {
	struct sr_packet *packet = req->packets;

    while (packet) {
        // send stuff here
        packet = packet->next;
    }
    // placeholder exit
    exit(0);
    
}
*/