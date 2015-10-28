#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*
sr_router must check if it's an IP packet
then call this function
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
    sr_ip_hdr_t *ip_packet = packet + sizeof(sr_ethernet_hdr_t);
    
    /* sanity check the IP packet */
    minLen = sizeof(sr_ip_hdr_t);

    if (ip_packet->ip_len) < minLen) {
        fprintf("Error: Invalid IP packet\n Length of the frame is incorrect\n");
        return ;
    } 

    uint8_t *icmp_cargo = ip_packet + sizeof(sr_ip_hdr_t);
    if (ip_packet->ip_sum != cksum(icmp_cargo)) {
        fprintf("Error: IP packet's checksum does not match\nDropping packet...\n");
        return ;
    }


    /* else this IP packet is valid: */
    
    /* Check the the ip packet is being sent to this host, sr_router */
    /* refer to sr_if.h*/
    if (sr->sr_addr != ip_packet->ip_dest) {
        fprintf("")
    } else {
    /* check if IP packet uses ICMP */
      if (ip_packet->ip_p == 1) {
      // create the ICMP echo reply packet to send
      sr_icmp_hdr_t echo_req_hdr = malloc(sizeof(icmp_hdr_t));

      echo_req_hdr->icmp_type = 0;
      echo_req_hdr->icmp_code = 0;
      echo_req_hdr->icmp_sum = cksum(&icmp_req_cargo);

      // send the ICMP packet
      /*the icmp packet does not have cargo, just empty data*/
      sr_send_packet(sr, echo_reply_hdr, sizeof(sr_icmp_hdr_t), iface);


     /* check if IP packet uses TCP or UDP */
      } else if (ip_packet->ip_p == 6 || ip_packet->ip_p == 14) {
      
          // create the ICMP port unreachable packet to sends
          sr_icmp_hdr_t echo_reply_hdr = malloc(sizeof(icmp_hdr_t));
          
          echo_reply_hdr->icmp_type = 3;
          echo_reply_hdr->icmp_code = 0;
          echo_reply_hdr->icmp_sum = cksum(&icmp_reply_cargo);

          // send the ICMP packet
          /*the icmp packet does not have cargo, just empty data*/
          sr_send_packet(sr, echo_req_hdr, sizeof(sr_icmp_hdr_t), iface);


      } else {
          fprintf(stderr, "Error: this IP packet uses an unrecognized protocol.\nDropping packet...\n");
      }
    
}