#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_ip.h"


/**
 * Return the interface that corresponds to the given IP address. 
 * @param  ip_addr an IP address
 * @param  if_list Linked list of interfaces to check for a matching IP address
 * @return         an interface
 */
struct sr_if* sr_get_if_from_ip (uint32_t ip_addr, struct sr_if* if_list) {
  struct sr_if *iface = if_list;

  /* Traverse through linked list of interfaces in if_list to find a matching interface*/
  while (iface) {
    if (ip_addr == iface->ip) {
      return iface;
    }

    iface = iface->next;
  }

  return NULL;
}


/**
 * Return the matching routing table entry that has the longest matching prefix against
 * the given ip address.
 * 
 * @param  ip_address     an IP address
 * @param  routing table  a linked list of routing entries
 * @return                a routing table entry
 */
struct sr_rt* lpm(uint32_t ip_addr, struct sr_rt *rtable) {
        struct sr_rt* longest_match = NULL;
        
        /* Loop through the linked list of routing entries in a table */
        struct sr_rt* current_node = NULL;
        current_node = routing_table;

        while (current_node){

            /* check if this entry's prefix matches with the given ip address */
            if ((ntohl(current_node->dest.s_addr) & ntohl(current_node->mask.s_addr)) 
                                    == (ntohl(ip_addr) & ntohl(current_node->mask.s_addr))){

                /* Check to see if this matching prefix is longer than our 
                   current longest matching prefix..update longest_match if it is*/
                if (longest_match == NULL || current_node->mask.s_addr > longest_match->mask.s_addr){
                    longest_match = current_node;
                }
            }
            /* move to the next entry in the routing table to find the longest matching prefix */
            current_node = current_node->next;
        }
        return longest_match;
}



/**
 * Forward a given IP packet to another interface is it is not to be sent to the previous router.
 * @param sr     an sr_instance
 * @param packet incoming raw frame
 * @param len    length of thise raw frame
 */
void forward_ip_packet(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_hdr->ip_ttl <= 1) {
    fprintf(stderr, "This packet's TTL expired!.\n Sending ICMP TIME EXCEEDED packet!\n");
    handle_ICMP(sr, TIME_EXCEEDED, packet, 0, 0);
    return;
  }

  ip_hdr->ip_ttl--;

  /* recompute the checksum */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  struct sr_rt *matching_entry = lpm(ip_hdr->ip_dst, sr->routing_table);
  if (!matching_entry) {
    fprintf(stderr, "LPM could not find a matching RT entry!\n Send ICMP NET UNREACHABLE packet\n");
    handle_ICMP(sr, NET_UNREACHABLE, packet, 0, 0);
    return;
  }

  lookup_and_send(sr, packet, len, matching_entry);
}