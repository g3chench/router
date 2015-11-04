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

/*
 * sr_router must check if it's an IP packet
 * then call this function
 */
struct sr_if *get_output_interface(struct sr_instance *sr, uint32_t address) {
  
  struct sr_if *current_node = sr->if_list;
  
  while (current_node) {
    if (address == current_node->ip) {
      return current_node;
    }
    current_node = current_node->next;
  }

  return NULL;
}

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


  uint16_t sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  // uint8_t *icmp_cargo = (uint8_t *) (ip_hdr + sizeof(sr_ip_hdr_t));
  // unsigned int cargo_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    
  if (sum != cksum(ip_hdr, iphdr->ip_hl * 4)) {
      uint16_t actualCkSum = 0;
      uint16_t expectedCkSum = 0;
      actualCkSum = cksum(ip_hdr, iphdr->ip_hl * 4);
      expectedCkSum = sum;
      fprintf(stderr,"TESTING: Actual Checksum is %i\n", actualCkSum);
      fprintf(stderr,"TESTING: Expected Checksum is %i\n", expectedCkSum);
      /*fprintf(stderr, "%i\n", sum);*/
      fprintf(stderr, "Error: Invalid IP packet\n Checksum does not match\nDropping packet...\n");
      return ;
  }


    /* else this IP packet is valid: */
    
    /* Check that the ip packet is being sent to this host, sr_router */
  struct sr_if *out_interface = get_output_interface(sr, ip_hdr->ip_dst);

  if (out_interface != NULL) {
        printf("This IP packet was sent to me!\n");
        /* check if IP packet uses ICMP */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            send_icmp_echo_request(sr, packet, in_interface);

        /* check if IP packet uses TCP or UDP */
        } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 14) {
            send_icmp_port_unreachable(sr, packet, in_interface);

        } else {
            fprintf(stderr, "Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
        }

  /* This packet was sent to me */
  } else {
      printf("Forward this packet to another router...\n");
      
      if (ip_hdr->ip_ttl <= 1) {
        fprintf(stderr, "Packet's TTL expired");
        send_icmp_time_exceeded(sr, packet, in_interface);
        return ;

      } else {
          /* forward the packet if new TTL > 0
          * search through linked list of nodes for forwarding
          * table entry using LPM.
          */

          struct sr_rt *current_node = sr->routing_table;

          while (current_node) {
              if (ip_hdr->ip_dst == (current_node->dest.s_addr & current_node->mask.s_addr)) {

                /* Build the outgoing ethernet frame to forward to another router */
                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) (packet);
                memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

                /* search for the new ethernet frame's destination MAC address ARP cache */
                struct sr_arpentry *current_arp = sr_arpcache_lookup(&sr->cache, current_node->gw.s_addr);
                
                /* found a hit in the ARP cache*/
                if (current_arp) {
                    memcpy(eth_hdr->ether_dhost, current_arp->mac, ETHER_ADDR_LEN);
                    ip_hdr->ip_ttl--;
                   /* remember ip_hl:4 in sr_protocol.h*/
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                    free(current_arp);
                    sr_send_packet(sr, (uint8_t *)(packet), len, current_node->interface);
                    return;

                /* No entry found in ARP cache, send ARP request */
                } else {
                    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, current_node->gw.s_addr, (uint8_t*)packet, len, (char*)interface);
                    handle_arpreq(sr, req);
                    /*ip_hdr->ip_ttl--; DO  I NEED THIS LINE??*/
                    return ;
                }
              }
              /* go to the next node in the rt_table */
              current_node = current_node->next;
          } /*end of while loop*/

          
          send_icmp_host_unreachable(sr, packet, in_interface);   
      }
      return;
  } /*end of else for line 78 if block */

  return;
} /* end of ip_handler function */
