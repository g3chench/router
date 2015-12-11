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
#include "sr_nat.h"

/**
 * Handle an IP packet:
 *   handle ICMP echo replies
 *   forward IP packet to next-hop router if it's destination is not this router. 
 * 
 * @param sr        sr instance
 * @param packet    incoming packet
 * @param len       length of this packet
 * @param interface interface this packet was sent through
 */
void handle_IP (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
    printf("in handle_IP()------------\n");
    struct sr_ip_hdr *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    printf("Perform packet sanity checks...\n");
    uint16_t expected_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t actual_cksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    
    /******Perform sanity checks **********88*/
    unsigned int min_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if (len < min_packet_len) {
      fprintf(stderr, "ERROR: Invalid packet length.\n");
      return;
    }

    if (actual_cksum != expected_cksum) {
      fprintf(stderr, "ERROR: checksum mismatch.\n");
      return;
    }
    ip_hdr->ip_sum = expected_cksum;

    /* if NAT is enabled */
    if (sr->nat != NULL) {
      handle_nat(sr, packet, len, interface);
      return;
    }

    /*printf("Passed IP packet sanity checks!\n");*/
    /****This packet is for us!*******/
    
    if (get_iface(ip_hdr->ip_dst, sr)) {
        printf("DAMNN 'DIS PACKET IS FOR US\n");

        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            printf("    icmp type, code: %d, %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);  
            
            if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {       /* handle icmp echo request */
                printf("    Got an ICMP ECHO REQUEST!\n");
                /* Sancheck: checksum */
                uint16_t icmp_expected_cksum = icmp_hdr->icmp_sum;
                icmp_hdr->icmp_sum = 0;
                uint16_t icmp_computed_cksum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
                
                if (icmp_expected_cksum == icmp_computed_cksum) {
                    icmp_hdr->icmp_sum = icmp_expected_cksum;
                    printf("    sending ICMP ECHO REPLY...\n");
                    handle_ICMP(sr, ECHO_REPLY, packet, len, 0);
                }
                else {
                    fprintf(stderr, "ERROR: mismatching ICMP checksums\n");
                }
            }
        }
        else if (ip_hdr->ip_p == ip_protocol_udp || ip_hdr->ip_p == ip_protocol_tcp) {
            handle_ICMP(sr, PORT_UNREACHABLE, packet, 0, ip_hdr->ip_dst);

        } else { /* ignore packet */
            fprintf(stderr, "ERROR: Unsupported IP protocol type.\n");
        }

    /******PACKET NOT FOR US, FORWARD IT TO NEXT HOP*/
    } else {
      forward_IP_packet(sr, packet, len);
    }
}

void forward_IP_packet(struct sr_instance* sr,
                       uint8_t * packet,
                       unsigned int len) {
  printf("    THIS PACKET AIN'T FOR US!\n    Forward it to the next router!\n");
  printf("    in forward_ip_pkt()------------\n");

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_hdr->ip_ttl <= 1) {
      fprintf(stderr, "packet's TTL expired! Send ICMP TIME EXCEEDED...\n");
      handle_ICMP(sr, TIME_EXCEEDED, packet, 0, 0);
      return;
  }

  /*reconstruct ip header*/
  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  printf("find outgoing interface to forward this packet through...\n");
  struct sr_rt *matching_entry = lpm(ip_hdr->ip_dst, sr->routing_table);
  if (!matching_entry) {
      fprintf(stderr, "LPM could not find a matching RT entry!\n Send ICMP NET UNREACHABLE packet\n");
      handle_ICMP(sr, NET_UNREACHABLE, packet, 0, 0);
      return;
  }

  /* send IP packet through outgoing interface*/
  cached_send(sr, packet, len, matching_entry);
}

/**
 * Return the interface that corresponds to the given IP address. 
 * @param  ip_addr an IP address
 * @param  if_list Linked list of interfaces to check for a matching IP address
 * @return         an interface
 */
struct sr_if* get_iface (uint32_t ip_addr, struct sr_instance *sr) {
  struct sr_if *iface = sr->if_list;
  printf("    in get_iface()------------\n");
  
  /* loop through linked list of interfaces to find interface
     corresponding to given IP adddr*/
  while (iface) {
      if (ip_addr == iface->ip) {
          printf("    found a matching interface!\n");
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
struct sr_rt* lpm(uint32_t ip_addr, struct sr_rt *routing_table) {
    printf("    in lpm()------------\n");
    struct sr_rt* matching_entry = NULL;
    struct sr_rt* current_node = NULL;
    current_node = routing_table;

    /*look through linked list routing table to find entry with longest prefix match*/
    while (current_node){

        /* check for prefix match */
        if ((ntohl(current_node->dest.s_addr) & ntohl(current_node->mask.s_addr)) 
          == (ntohl(ip_addr) & ntohl(current_node->mask.s_addr))){

              /*update current LPM if necessary*/
              printf("    Check if this entry contains longer matching LPM\n");
              if (matching_entry == NULL || current_node->mask.s_addr > matching_entry->mask.s_addr){
                  printf("    found entry with longer prefix match--update LPM\n");
                  matching_entry = current_node;
              }
        }
        current_node = current_node->next;
    }

    if (matching_entry) {
        printf("    Found an LPM match!\n");
    } else {
        printf("    Coudn't find LPM match :(\n");
    }
    return matching_entry;
}