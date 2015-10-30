#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_ip_handler.h"
#include "sr_icmp_handler.h"

/*
 * sr_router must check if it's an IP packet
 * then call this function
 */
void ip_handler(struct sr_instance* sr, 
        uint8_t *packet,
        unsigned int len, 
        char *interface) {

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
    uint8_t *ip_pkt;
    //fprintf(stdout, "Received IP %s from %s on %s\n", 
    //                ip_hdr->ip==ip_protocol_icmp?"ICMP":"IP", 
    //                ip_)


    /* sanity check the IP packet */
    size_t min_len = sizeof(sr_ip_hdr_t);

    if (ip_hdr->ip_len < min_len) {
        fprintf(stderr, "Error: Invalid IP packet\n Length of the frame is incorrect\nDropping packet...\n");
        return ;
    } 

    uint8_t *icmp_cargo = (uint8_t *) (ip_hdr + sizeof(sr_ip_hdr_t));
  	unsigned int cargo_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      
  	if (ip_hdr->ip_sum != cksum(icmp_cargo, cargo_len)) {
          fprintf(stderr, "Error: Invalid IP packet\n Checksum does not match\nDropping packet...\n");
          return ;
    }


    /* else this IP packet is valid: */
    
    /* Check that the ip packet is being sent to this host, sr_router */
    /* refer to sr_if.h*/
    int sent_to_me = 0;
    struct sr_if* current_interface = sr->if_list;
    while (current_interface) {
        if (sr_get_interface_from_ip(sr, ip_hdr->ip_dst) == current_interface->addr){
            sent_to_me = 1;
            break;
        }
		current_interface = current_interface->next;
    }

    if (sent_to_me == 1) {
        printf("This IP packet was sent to me!\n");
        /* check if IP packet uses ICMP */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            send_icmp_echo_request(sr, packet, len, interface);

        /* check if IP packet uses TCP or UDP */
        } else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 14) {
            send_icmp_port_unreachable(sr, packet, len, interface);

        } else {
            fprintf(stderr, "Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
        }


    } else {
        printf("Forward this packet to another router...\n");
        
        if (ip_hdr->ip_ttl <= 1) {
          fprintf(stderr, "Packet's TTL expired")
          send_icmp_time_exceeded(sr, ip_hdr, len, char *interface);
          return ;

        } else {
            /* search through linked list of nodes for forwarding
            * table entry using LPM.
            */
            struct sr_rt *current_node = sr->routing_table;
            
            while (node) {
              if (current_node->dest.s_addr == ip_hdr->mask.s_addr & ip_hdr->ip_dest) {

                  /* Build the outgoing ethernet frame to forward to another router */
                  struct sr_if *out_interface = sr_get_interface(sr, current_entry->interface);
                  struct sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) (packet);
                  
                  memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

                  // search for the new ethernet frame's destination MAC address ARP cache
                  struct sr_arpentry *current_arp = sr_arpcache_lookup(&(sr->cache), current_node->gw.s_addr);
                  
                  /* found a hit in the ARP cache*/
                  if (current_arp) {
                      memcpy(eth_hdr->ether_dhost, current_arp->mac, ETHER_ADDR_LEN);
                      ip_hdr->ip_ttl--;
                      /* remember ip_hl:4 in sr_protocol.h*/
                      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl*4);
                      free(current_arp);
                      sr_send_packet(sr, packet, len, current_node->interface);
                      return;

                  } else {
                      /* Cannot find a routing table entry. We try to request */
                      send_arp_req(sr, sr_arpcache_queuereq(&(sr->cache), current_node->gw.s_addr, packet, len, interface));
                      return ;
                  }
                }
              }

              /* go to the next node in the rt_table */
              current_node = current_node->next;
            }
          
          return;
        }

    return;
}
