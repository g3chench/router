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
  /*
              Ethernet frame
    --------------------------------------------
    | Ethernet hdr |       IP Packet           |
    --------------------------------------------

                    ----------------------------
                    | IP hdr |   IP Packet     |
                    ----------------------------
  */
  /* store the ip packet from the ethernet frame */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  /* fprintf(stdout, "Received IP %s from %s on %s\n", 
                  ip_hdr->ip==ip_protocol_icmp?"ICMP":"IP", 
                  ip_)
  */


  /* sanity check the IP packet */
  size_t min_len = sizeof(sr_ip_hdr_t);

  if (ip_hdr->ip_len < min_len) {
      fprintf(stderr, "Error: Invalid IP packet\n Length of the frame is incorrect\nDropping packet...\n");
      return ;
  } 

  uint16_t expectedSum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t actualSum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
 
  if (expectedSum != actualSum) {
      fprintf(stderr,"TESTING: Expected Checksum is %i\n", expectedSum);
      fprintf(stderr,"TESTING: Actual Checksum is %i\n", actualSum);
      fprintf(stderr, "Error: Invalid IP packet\n Checksum does not match\nDropping packet...\n");
      return ;
  }

  ip_hdr->ip_sum = expectedSum;

  /* else this IP packet is valid: */
    
  /* Check that the ip packet is being sent to this host, sr_router */
  struct sr_if *out_interface = get_output_interface(sr, ip_hdr->ip_dst);

  if (out_interface != NULL) {
      printf("This IP packet was sent to me!\n");
      /* check if IP packet uses ICMP */
      if (ip_hdr->ip_p == 1) {
        printf("GOT AN ICMP PACKET\n");
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        if (icmp_hdr->icmp_code == 0 && icmp_hdr->icmp_type == 8) {
          printf("got an ECHO REQUEST\n");
          send_icmp_echo_reply(sr, packet, in_interface);
        }

      /* check if IP packet uses TCP or UDP */
      } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17) {
          printf("GOT A TCP/UDP PACKET\n");
          send_icmp_port_unreachable(sr, packet, in_interface);

      } else {
          fprintf(stderr, "Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
      }

  /* This packet was not sent to me */
  } else {
      printf("Forward this packet to another router...\n");
      
      if (ip_hdr->ip_ttl == 1) {
        fprintf(stderr, "Packet's TTL is 1");
        send_icmp_echo_request(sr, packet, in_interface);

      } else if (ip_hdr->ip_ttl < 1) {
        fprintf(stderr, "Packet's TTL expired");
        send_icmp_time_exceeded(sr, packet, in_interface);
        return ;

      } else {
          /* forward the packet if new TTL > 0
          * search through linked list of nodes for forwarding
          * table entry using LPM.
          */
          printf("Forward this packet to another router...\n");
          struct sr_rt *current_node = sr->routing_table;

          printf("BEGIN LPM SEARCH ==============================================================\n");
          while (current_node) {

              printf("ITERATION: CURRENT node-------------------------------\n");
              printf("ip and node mask       : %i\n", (ip_hdr->ip_dst & current_node->mask.s_addr));
              printf("dest addr and node_mask: %i\n", (current_node->dest.s_addr & current_node->mask.s_addr));
              
               /* perform LPM */
              if ((ip_hdr->ip_dst & current_node->mask.s_addr) == (current_node->dest.s_addr & current_node->mask.s_addr)) {
                printf("We found a LPM match...\n");
                break;
              }

              /* go to the next node in the rt_table */
              current_node = current_node->next;
          }

          printf("Now out of the loop..-------------------\n");
         
          /* Build the outgoing ethernet frame to forward to another router */
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) (packet);
          /* printf("TESTING: HERE 0\n");*/

          struct sr_if* fwd_out_if = sr_get_interface(sr, current_node->interface);
          memcpy(eth_hdr->ether_shost, fwd_out_if->addr, ETHER_ADDR_LEN);

          /*printf("TESTING: HERE 1\n");*/
          /* search for the next hop MAC address in the cache */
          
          struct sr_arpentry *current_arp = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
          printf("Check if this mac address exists =========================\n");
          printf("current_arp->ip: %i\n", current_arp->ip);

          /* found a hit in the ARP cache*/
          if (current_arp) {
              printf("FOUND AN ARPCACHE HIT!\n");
              /*printf("TESTING: Current Arp..\n");*/
              memcpy(eth_hdr->ether_dhost, current_arp->mac, ETHER_ADDR_LEN);
              memcpy(eth_hdr->ether_shost, fwd_out_if->addr, ETHER_ADDR_LEN);
             
              /* NOTE!: FIGURE THIS OUT LATER FIONA: remember ip_hl:4 in sr_protocol.h*/ 
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = 0;
              ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
              free(current_arp);
              sr_send_packet(sr, (uint8_t *)(packet), len, current_node->interface);
              return;

          /* No entry found in ARP cache, send ARP request */
          } else {
              printf("TESTING: No entry found in ARP Cache\n");
              struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, current_node->gw.s_addr, (uint8_t*)packet, len, (char*)interface);
              handle_arpreq(sr, req);
              /*ip_hdr->ip_ttl--; DO  I NEED THIS LINE??*/
              return ;
          }
        

          send_icmp_host_unreachable(sr, packet, in_interface);   
      }
      return;
  }

  return;
} /* end of ip_handler function */
