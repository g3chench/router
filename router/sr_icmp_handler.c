#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>

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

void handle_icmp(int type, int code, struct sr_instance* sr, 
				uint8_t* old_pkt, uint32_t sender, struct sr_if* iface) {

	printf("\nIN FUNCTION: gen_icmp_hdr--------------------------------------------\n");
	printf("Creating an ethernet frame containing an ICMP packet\n");

    /* Construct and fill in the ethernet, IP and ICMP headers */

    /* Construct ethernet header*/
	sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t *)old_pkt;
	sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(old_pkt + sizeof(sr_ethernet_hdr_t));

	
	struct sr_rt* rt_entry = lpm(old_ip_hdr->ip_src, sr->routing_table);
    if (!rt_entry) {
    	printf("Error: LPM cannot find a matching arp entry\n");
    	return;
    }

	uint8_t* new_pkt;
	int new_len;
	if (type == 3) {
		new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
		new_pkt = (uint8_t *)malloc(new_len);
	} else {
		new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
		new_pkt = (uint8_t *)malloc(new_len);
	}
	printf("check that new_pkt has been initialized correctly: sizeof(new_pkt) = %i", sizeof(new_pkt));

	/* CREATE AN ETHERNET HEADER, leave src and dest unset for now, will set them later */
	printf("\ncreating eth hdr------------------------------\n");
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)(new_pkt);
	gen_eth_hdr(eth_hdr, 0, 0, htons(ethertype_ip)); 
	print_hdr_eth(eth_hdr);

	printf("\ncreating ip hdr------------------------------\n");
	/* CONSTRUCT IP HEADER */
	sr_ip_hdr_t* ip_hdr = new_pkt + sizeof(sr_ethernet_hdr_t);
	ip_hdr->ip_p = ip_protocol_icmp;

	/* when icmp host unreachable, send packet to the sender, otherwise use next hop's ip */
	if (!sender && type != 0) {
		struct sr_if* out_if = sr_get_interface(sr, rt_entry->interface);
		sender = out_if->ip;
	}

	if (type == 0) {
		printf("create header for ICMP ECHO REPLY...\n");
		gen_ip_hdr(ip_hdr, old_ip_hdr->ip_dst, old_ip_hdr->ip_src, sizeof(sr_icmp_hdr_t), ip_protocol_icmp);
		ip_hdr->ip_ttl = INIT_TTL;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(old_ip_hdr, old_ip_hdr->ip_hl*4);

	} else if (type == 3 || type == 11) {
		printf("Create ip header for non 0 ICMP pkt...\n");
		gen_ip_hdr(ip_hdr, sender, old_ip_hdr->ip_src, sizeof(sr_icmp_t3_hdr_t), ip_protocol_icmp);
	}
	print_hdr_ip(ip_hdr);

	printf("\ncreating icmp hdr------------------------------\n");
	/* CONSTRUCT ICMP HEADER */
	sr_icmp_hdr_t* icmp_hdr = new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
	gen_icmp_hdr((uint8_t *)icmp_hdr, type, code, old_pkt);
	printf("FULLY CONSTRUCTED PACKET IS READY\n");
	
	print_hdr_icmp(icmp_hdr);
	
	cached_send(sr, new_pkt, new_len, rt_entry);
}


void send_icmp_echo_reply(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING ICMP ECHO REPLY\n");
	handle_icmp(0, 0, sr, packet, sender, interface);
}


void send_icmp_echo_request(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING ICMP ECHO REquest\n");
	handle_icmp(8, 0, sr, packet, sender, interface);
}


void send_icmp_net_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING ICMP NET UNREACHABLE\n");
	handle_icmp(3, 0, sr, packet, sender, interface);
}


void send_icmp_host_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING HOST UNREACHABLE\n");
	handle_icmp(3, 1, sr, packet, sender, interface);
}


void send_icmp_port_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING ICMP port UNREACHABLE\n");
	handle_icmp(3, 3, sr, packet, sender, interface);
}


void send_icmp_time_exceeded(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface) {
	printf("SENDING ICMP TIME EXCEEDED\n");
	handle_icmp(11, 0, sr, packet, sender, interface);
}


/**
 * Search the ARP cache for an entry with the correct MAC address and outgoing
 * interface to forward a given packet through. 
 */
void cached_send(struct sr_instance* sr, uint8_t* packet, int len, struct sr_rt* rt_entry) {
  printf("\nIN FUNCTION: cached_send--------------------------------------------\n");
  struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);
  /* this is ethernet frame containing he packet*/
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) (packet);

  /* found a hit in the ARP cache*/
  if (arp_entry) {
      printf("FOUND AN ARPCACHE HIT!\n");
      /* Build the outgoing ethernet frame to forward to another router */
      struct sr_if* fwd_out_if = sr_get_interface(sr, rt_entry->interface);
      memcpy(eth_hdr->ether_shost, fwd_out_if->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, arp_entry->mac, ETHER_ADDR_LEN);
      print_hdr_eth((uint8_t*) eth_hdr);
      printf("this is the interface\n");
      sr_print_if(fwd_out_if);
      printf("Sending packets\n");
      sr_send_packet(sr, packet, len, fwd_out_if->name);
      printf("Freeing arp_entry\n");
      free(arp_entry);
      printf("IP_Handler ends here dawg\n");

  } else {
      /* No entry found in ARP cache, send ARP request */
      /* printf("TESTING: No entry found in ARP Cache\n");
      prinf("reqeust an entry. send ARP REQUEST\n");
      */
      /* Cache doesnt have this entry, So request it */ 
      printf("Coudln't find arp cache hit, handlearp\n");
      struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache),
                                                  rt_entry->gw.s_addr,
                                                  (uint8_t*) eth_hdr,
                                                  len,
                                                  rt_entry->interface);
      assert(req != NULL);
      /* send the ARP request packet*/
      handle_arpreq(sr, req);
  }
}




/**
 * Create an ICMP packet given a type and code, then store it in a given ethernet packet
 * "packet".
 * @param destination   pointer to where we store this ICMP hdr at
 * @param type          ICMP type, int
 * @param code          ICMP code, int
 * @param old_pkt       old packet passed in
 */
void gen_icmp_hdr (uint8_t* destination, int type, int code, uint8_t *old_pkt) {
	printf("\nIN FUNCTION: gen_icmp_hdr--------------------------------------------\n");
	sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(old_pkt + sizeof(sr_ethernet_hdr_t));
	
	if (type == 0) {
		sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)destination;
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(old_ip_hdr->ip_len) - (old_ip_hdr->ip_hl*4));

		memcpy(destination, icmp_hdr, sizeof(sr_icmp_hdr_t));

	} else if (type == 3) {
		if ((code == 0) || (code == 1) || (code != 3)) {
			sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)destination;

			icmp_hdr->icmp_type = type;
			icmp_hdr->icmp_code = code;
			icmp_hdr->unused = 0;
			icmp_hdr->next_mtu = htons(512);
			memcpy(icmp_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);
			icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(old_ip_hdr->ip_len) - (old_ip_hdr->ip_hl*4));
			
			memcpy(destination, icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

		} else {
			printf("Unsupported ICMP code for type 3 ICMP.\n");
		}

	} else {
		/* ICMP type: unsupported*/
		fprintf(stderr, "unsupported ICMP type\n");
	}
}

/**
 * Create an ethernet header and and store it at the pointer <packet>
 * @param destination   pointer of where to store this IP header
 * @param src           mac address
 * @param dst           mac address
 * @param protocol      protocol type
 */
void gen_ip_hdr(sr_ip_hdr_t* destination, uint32_t src, uint32_t dst, uint16_t cargo_size, uint8_t protocol) {
	printf("\nIN FUNCTION: gen_ip_hdr--------------------------------------------\n");
	
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(destination);

	ip_hdr->ip_hl = 5;
	ip_hdr->ip_v = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + cargo_size);
	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = INIT_TTL;
	ip_hdr->ip_p = protocol;
	ip_hdr->ip_src = src;
	ip_hdr->ip_dst = dst;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);

	memcpy(destination, ip_hdr, sizeof(sr_ip_hdr_t));
}


/**
 * Create an ethernet header and store it at the pointer "packet"
 * @param  destination    pointer of where to store this eth hdr
 * @param  ETHER_ADDR_LEN [description]
 * @param  dest           dest mac addr
 * @param  ether_type     src mac addr
 */
void gen_eth_hdr(sr_ethernet_hdr_t* destination, uint8_t src[ETHER_ADDR_LEN], 
				uint8_t dest[ETHER_ADDR_LEN], uint16_t type) {

	printf("\nIN FUNCTION: gen_eth_hdr--------------------------------------------\n");
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(destination);
	memcpy(eth_hdr->ether_shost, src, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(type);

	memcpy(destination, eth_hdr, sizeof(sr_ethernet_hdr_t));
}


/** dest_ip = ip_hdr->ip_dst*/
struct sr_rt* lpm(struct sr_rt* routing_table, uint32_t ip_addr) {
    printf("\nIN FUNCTION: LPM--------------------------------------------\n");
    struct sr_rt *current_node = routing_table;
    struct sr_rt* matching_entry = NULL;
    unsigned long matching_len = 0;
    while (current_node) {
        printf("Current node\n");
        sr_print_routing_entry(current_node);
        /* Perform LPM matching*/
        if (((ip_addr & current_node->mask.s_addr) == (current_node->dest.s_addr & current_node->mask.s_addr))
                  & (matching_len <= current_node->mask.s_addr)) {

        	printf("This is a match\n");
        	matching_entry = current_node;
        	matching_len = current_node->mask.s_addr;
        	break;
        }

        /* go to the next node in the rt_table */
        current_node = current_node->next;
    }
    return matching_entry;
}