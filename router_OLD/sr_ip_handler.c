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
void ip_handler(struct sr_instance* sr, 
        uint8_t* packet,
        unsigned int len, 
        char *interface) {
  printf("TESTING: In ip_handler function..\n");
  struct sr_if* in_interface = (struct sr_if*) interface;
 
  /* store the ip packet from the ethernet frame */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* sanity check the IP packet */
  size_t min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (len < min_len) {
      fprintf(stderr, "Error: Invalid IP packet\nLength of the frame is incorrect\nDropping packet...\n");
      return ;
  } 

  /* calculate the checksum*/
  uint16_t expected_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  int ip_hl =ip_hdr->ip_hl * 4;
  uint16_t actual_sum = 0; 
  actual_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
 
  if (expected_sum != actual_sum) {
      fprintf(stderr,"TESTING: Expected Checksum is %i\n", expected_sum);
      fprintf(stderr,"TESTING: Actual Checksum is %i\n", actual_sum);
      fprintf(stderr, "Error: Invalid IP packet\n Checksum does not match\nDropping packet...\n");
      return ;
  }
  ip_hdr->ip_sum = expected_sum;
  
  /* else this IP packet is valid: */
  /* Check that the ip packet is being sent to this host, sr_router */
  struct sr_if *out_interface = get_output_interface(sr->if_list, ip_hdr->ip_dst);

  /* PACKET SENT TO ME */
  if (out_interface != NULL) {
      printf("This IP packet was sent to me!\n");
      uint8_t ip_protocol = ip_hdr->ip_p;

      switch (ip_protocol) {
        case ip_protocol_icmp: {
          printf("This IP packet contains an ICMP packet.\n");
          sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          
          if (icmp_hdr->icmp_code == 0 && icmp_hdr->icmp_type == 8) {
            printf("got an ECHO REQUEST\n");
            

            /* sanity check the ICMP packet*/
            uint16_t icmp_expected_sum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = 0;
            uint16_t icmp_actual_sum = 0;
            icmp_actual_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
            
            if (icmp_expected_sum == icmp_actual_sum) {
              icmp_hdr->icmp_sum = icmp_expected_sum;
              send_icmp_echo_reply(sr, packet, 0, in_interface);  
            } else {
              fprintf(stderr, "Error: Invalid ICMP echo request.\n Checksum does not match...\n");
            }
            
          } /* End of icmp packet checksum matching*/
        } /* end of icmp case*/
        case ip_protocol_tcp: {
          printf("This IP packet contains a TCP packet\n");
          send_icmp_port_unreachable(sr, packet, 0, in_interface);
        }
        case ip_protocol_udp: {
          printf("This IP packet contains a UDP packet\n");
          send_icmp_port_unreachable(sr, packet, 0, in_interface);
        }
        default: {
          printf("Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
        }
      }

  /* PACKET NOT SENT TO ME */
  } else {
      printf("THIS PACKET WAS NOT SENT TO ME!...\n");
      
      if (ip_hdr->ip_ttl <= 1) {                  /* TTL = 0, expired packet*/
        fprintf(stderr, "Packet's TTL expired");
        send_icmp_time_exceeded(sr, packet, 0, in_interface);
        return;

      } else {
          /* forward the packet if new TTL > 0
          * search through linked list of nodes for forwarding
          * table entry using LPM.
          */
          printf("This packet is not for us. Forward this packet to another router...\n");
          ip_hdr->ip_ttl--;
          if (ip_hdr->ip_ttl == 0) {
            printf("packet timed out! TTL = 0\n");
            send_icmp_time_exceeded(sr, packet, 0, in_interface);
          }

          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
          
          /* Use LPM for routing table lookup*/
          struct sr_rt* matching_entry = lpm(sr->routing_table, ip_hdr->ip_dst);          
          if (matching_entry) {
              printf("matching RT entry found\n");
              printf("send thru cached mac address and interface\n");
              printf("calling cached_send\n");
              cached_send(sr, packet, len, matching_entry);
              
          /* end of: if matching routing table entry is found */
              
          } else {
              printf("no matching rt entry found \n");
              send_icmp_host_unreachable(sr, packet, 0, in_interface);
              return ;
          }

      }
  }

  return;
} /* end of ip_handler function */
