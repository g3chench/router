#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_ip_handler.h"
#include "sr_icmp_handler.h"
#include "sr_arp_handler.h"

struct sr_if *get_output_interface(struct sr_instance *sr, uint32_t address) {

  printf("TESTING: BEFORE current_node\n");
  struct sr_if *current_node = sr->if_list;
  printf("TESTING: AFTER current_node\n");
  
  while (current_node) {
    if (address == current_node->ip) {
      printf("TESTING: FIRST return\n");
      return current_node;
    }
    current_node = current_node->next;
  }

  printf("TESTING: SECOND return\n");
  return NULL;
}

struct sr_rt* lpm(struct sr_instance* sr, uint8_t* packet, struct sr_if* in_interface, sr_ip_hdr_t* ip_hdr) {
    struct sr_rt *current_node = sr->routing_table;

          printf("BEGIN LPM SEARCH ==============================================================\n");
          printf("==========================================================\n");
          struct sr_rt* matching_entry = NULL;
          unsigned long matching_len = 0;

          while (current_node) {
              printf("ITERATION: CURRENT node-------------------------------\n");
              printf("ip and node mask       : %i\n", (ip_hdr->ip_dst & current_node->mask.s_addr));
              printf("dest addr and node_mask: %i\n", (current_node->dest.s_addr & current_node->mask.s_addr));
              printf("matching_len: %lu\n", matching_len);
               /* perform LPM */
              if (((ip_hdr->ip_dst & current_node->mask.s_addr) == (current_node->dest.s_addr & current_node->mask.s_addr))
                        & (matching_len <= current_node->mask.s_addr)) {
                printf("We found a LPM match...\n");
                matching_entry = current_node;
                matching_len = current_node->mask.s_addr;
                break;
              }

              /* go to the next node in the rt_table */
              current_node = current_node->next;
          }


          printf("Now out of the loop..-------------------\n");
         
          if (!matching_entry) {
              printf("There is no matching entry in the forwarding table\n");
              printf("sending ICMP NET UNREACHABLE!!!!\n");
              /* No possible route to our destination, send ICMP Net unreachable message*/
              send_icmp_net_unreachable(sr, packet, in_interface);
          } else {
             printf("THERE'S A MATCHING DAMN ENTRY IN THE FORWARDING TABLE\n");
             printf("and here's the DAMN THING:\n");
             sr_print_routing_entry(matching_entry);
          }

          return matching_entry;
}


/**
 * Return the ARP entry if found in the arpcache given the ethernet header and LPM entry.
 * Null is returned otherwise.
 */
struct sr_arpentry* search_arpcache(struct sr_instance* sr, uint8_t* packet, struct sr_rt* matching_entry) {

    printf("SEARCH FOR MAC ADDR THRU ARP CACHE ================================\n");
    struct sr_arpcache* cache = &(sr->cache);
    /* search for the next hop MAC address in the cache */ 
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(cache, matching_entry->gw.s_addr);
    /* printf("sr cache first etry %i\n", (sr->cache.entries->ip));*/
    printf("Check if this mac address exists ========================================\n");
    
    return arp_entry;
}




/*
 * sr_router must check if it's an IP packet
 * then call this function
 */
void ip_handler(struct sr_instance* sr, 
        uint8_t* packet,
        unsigned int len, 
        char *interface) {
  printf("TESTING: In ip_handler function..\n");
  struct sr_if* in_interface = (struct sr_if*) interface;
 
  /* store the ip packet from the ethernet frame */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  /* fprintf(stdout, "Received IP %s from %s on %s\n", 
                  ip_hdr->ip==ip_protocol_icmp?"ICMP":"IP", 
                  ip_)
  */

  /* sanity check the IP packet */
  size_t min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (len < min_len) {
      fprintf(stderr, "Error: Invalid IP packet\n Length of the frame is incorrect\nDropping packet...\n");
      return ;
  } 

  /* calculate the checksum*/
  uint16_t expectedSum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t actualSum = 0;
  actualSum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
 
  if (expectedSum != actualSum) {
      fprintf(stderr,"TESTING: Expected Checksum is %i\n", expectedSum);
      fprintf(stderr,"TESTING: Actual Checksum is %i\n", actualSum);
      fprintf(stderr, "Error: Invalid IP packet\n Checksum does not match\nDropping packet...\n");
      return ;
  }


  /* else this IP packet is valid: */
  /* Check that the ip packet is being sent to this host, sr_router */
  struct sr_if *out_interface = get_output_interface(sr, ip_hdr->ip_dst);

  /* PACKET SENT TO ME */
  if (out_interface != NULL) {
      printf("This IP packet was sent to me!\n");
      uint8_t ip_protocol = htons(ip_hdr->ip_p);

      switch (ip_protocol) {
        case ip_protocol_icmp: {
          printf("This IP packet contains an ICMP packet.\n");
          sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          
          if (icmp_hdr->icmp_code == 0 && icmp_hdr->icmp_type == 8) {
            printf("got an ECHO REQUEST\n");
            send_icmp_echo_reply(sr, packet, in_interface);
          }
        }
        case ip_protocol_tcp: {
          printf(stderr, "This IP packet contains a TCP packet\n");
          send_icmp_port_unreachable(sr, packet, in_interface);
        }
        case ip_protocol_udp: {
          printf(stderr, "This IP packet contains a UDP packet\n");
          send_icmp_port_unreachable(sr, packet, in_interface);
        }
        default: {
          printf(stderr, "Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
        }
      }

  /* PACKET NOT SENT TO ME*/
  } else {
      printf("Forward this packet to another router...\n");
      
      if (ip_hdr->ip_ttl == 1) {                        /* TTL = 0 send ICMP echo request */
        fprintf(stderr, "Packet's TTL is 1");
        send_icmp_echo_request(sr, packet, in_interface);

      } else if (ip_hdr->ip_ttl < 1) {                  /* TTL = 0, expired packet*/
        fprintf(stderr, "Packet's TTL expired");
        send_icmp_time_exceeded(sr, packet, in_interface);

      } else {
          /* forward the packet if new TTL > 0
          * search through linked list of nodes for forwarding
          * table entry using LPM.
          */
          printf("This packet is not for us. Forward this packet to another router...\n");
          
          struct sr_rt* matching_entry = lpm(sr, packet, in_interface, ip_hdr);
          struct sr_arpentry* arp_entry = search_arpcache(sr, packet, matching_entry);
          /* this is ethernet frame containing he packet*/
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) (packet);
          print_hdr_eth((uint8_t*) eth_hdr);

          /* found a hit in the ARP cache*/
          if (arp_entry) {
              printf("FOUND AN ARPCACHE HIT!\n");
              /* Build the outgoing ethernet frame to forward to another router */
              memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
              
              /* Get the ethernet frame's outgoing interface */
              struct sr_if* fwd_out_if = sr_get_interface(sr, matching_entry->interface);
              memcpy(eth_hdr->ether_shost, fwd_out_if->addr, ETHER_ADDR_LEN);
              sr_print_if(fwd_out_if);
              /* fill in other ethernet attributes */
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = 0;
              ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
              sr_send_packet(sr, packet, len, fwd_out_if->name);
              free(arp_entry);

          } else {
              /* No entry found in ARP cache, send ARP request */
              /*    printf("TESTING: No entry found in ARP Cache\n");
              prinf("reqeust an entry. send ARP REQUEST\n");

              memset(eth_hdr->ether_dhost, 0, sizeof(uint8_t) * 6);
              uint8_t *packet = (uint8_t*)malloc(sizeof(uint8_t)*(sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + sizeof(sr_icmp_hdr_t) + ICMP_DATA_SIZE)); */
              /* Cache doesnt have this entry, So request it */
              struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache,
                                                          matching_entry->gw.s_addr,
                                                          (uint8_t*) eth_hdr,
                                                          len + sizeof(sr_ethernet_hdr_t),
                                                          matching_entry->interface);
              assert(req!=NULL);
              /* send the ARP request packet*/
              handle_arpreq(sr, req);

              printf("DONE\n");
          }

      }
  }

  return;
} /* end of ip_handler function */
