#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_ip.h"
#include "sr_icmp.h"



/**
 * Return an ethernet frame containing an ICMP message given an ICMP packet to process. 
 * @param sr         sr_instance
 * @param type       ICMP message type
 * @param old_packet raw packet to process
 * @param old_len    length of raw packet to process
 * @param sender_ip  IP address of the sender
 */
void handle_ICMP (struct sr_instance* sr, int type, uint8_t* old_packet, int old_len, uint32_t sender_ip) {

  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *matching_lpm_entry = lpm(old_ip_hdr->ip_src, sr->routing_table);
  if (!matching_lpm_entry) {
      fprintf(stderr, "ERROR: no longest prefix match\n");
      return;
  }

  if (!sender_ip && type != ECHO_REPLY) {
      struct sr_if* out_if = sr_get_interface(sr, matching_lpm_entry->interface);
      sender_ip = out_if->ip;
  }

  /* Create and send ethernet frame for ICMP ECHO REPLY*/
  if (type == ECHO_REPLY) {
      uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t)  + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
      
      /*sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_packet;
      eth_hdr->ether_type = htons(ethertype_ip);*/

      sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
      gen_ip_hdr(new_ip_hdr, old_len, old_ip_hdr->ip_p, old_ip_hdr->ip_dst, old_ip_hdr->ip_src);
      gen_icmp_hdr(type, old_packet, old_packet);

      cached_send(sr, old_packet, old_len, matching_lpm_entry);
    
    /* Create and send ethernet frame for ICMP HOST_[x] or ICMP TIME EXCEEDED */
  } else {
      int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
      uint8_t *new_packet = malloc(packet_len);
      
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_packet;
      eth_hdr->ether_type = htons(ethertype_ip);
      
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
      gen_ip_hdr(ip_hdr, old_len, ip_protocol_icmp, sender_ip, old_ip_hdr->ip_src);
      gen_icmp_hdr(type, new_packet, old_packet);

      cached_send(sr, new_packet, packet_len, matching_lpm_entry);
      
      free(new_packet);
  }
}



/**
 * Fill in the ICMP header given its pointer. 
 * @param type       ICMP type
 * @param buf        [description]
 * @param old_packet [description]
 */
void gen_icmp_hdr(int type, uint8_t *buf, uint8_t *old_packet) {
  printf("In gen_icmp_hdr()-----------\n");

  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(old_packet + sizeof(sr_ethernet_hdr_t));
  
  /* fill in a type 0: ICMP ECHO REPLY header */
  if (type == ECHO_REPLY) {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(new_ip_hdr->ip_len) - new_ip_hdr->ip_hl * 4);
  
  } else {
    /* Otherwise fill in a type 3: ICMP X UNREACHABLE header */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    switch (type) {
      case NET_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 0;

      case HOST_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 1;

      case PORT_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 3;
      
      case TIME_EXCEEDED:
        icmp_hdr->icmp_type = 11;
        icmp_hdr->icmp_code = 0;

      default: 
        fprintf(stderr, "ERROR: The inputted ICMP type is invalid. \n");  
    }

    icmp_hdr->unused = 0;

    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, old_ip_hdr, ICMP_DATA_SIZE);

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(new_ip_hdr->ip_len) - new_ip_hdr->ip_hl * 4);
  }
}



/**
 * Fill in the given IP header with the specifed length, protocol, source and destination IP.
 * @param ip_hdr   pointer to an IP header
 * @param len      length of this IP header's cargo
 * @param protocol IP protocol type which can be ICMP, TCP or UDP.
 * @param src      source IP address
 * @param dst      destination IP address
 */
void gen_ip_hdr(struct sr_ip_hdr *ip_hdr, uint16_t len, uint8_t protocol, uint32_t src, uint32_t dst) {
    printf("in gen_ip_hdr() -----------\n");

    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + len);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
}



/**
 * Fill in the given ethernet header with the given source, destination and ether_type.
 * @param eth_hdr  pointer to an ethernet header to fill in
 * @param dest     destination IP address
 * @param src      source IP address
 * @param type     ethernet type, either IP or ARP
 */
void gen_eth_hdr(struct sr_ethernet_hdr *eth_hdr, uint8_t  dest[ETHER_ADDR_LEN], 
              uint8_t  src[ETHER_ADDR_LEN], uint16_t type) {
    printf("In gen_eth_hdr");
    
    memcpy(eth_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, src, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(type);
}