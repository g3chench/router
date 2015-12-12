#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

/* len: is in bytes */
uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    /* connect first byte (8 bits) with second byte, 
     * need to shift over first byte first
     */
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}


/* 
  This function populates IP hdr.
*/

void populate_ip_hdr(struct sr_ip_hdr *ip_hdr, uint16_t data_len, uint8_t protocol, uint32_t src, uint32_t dst)
{
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + data_len);
    ip_hdr->ip_id = 0x0000;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = protocol;
    ip_hdr->ip_src = src;
    ip_hdr->ip_dst = dst;

    /* Calculate Checksum */
    ip_hdr->ip_sum = 0x0000; /* Make sure checksum is zeroed out before calculating */
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
}

/* 
  This function populates ICMP header. 
*/
void populate_icmp_hdr(int icmp_type, uint8_t *buf, uint8_t *original_packet){
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
	int ip_hl = ip_hdr->ip_hl * 4;

  sr_ip_hdr_t *original_ip_hdr = (sr_ip_hdr_t *)(original_packet + sizeof(sr_ethernet_hdr_t));
	
  if (icmp_type == ICMP_ECHOREPLY) { /* Type 0 header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
  }
  else {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    if (icmp_type == ICMP_NETUNREACHABLE) {
      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 0;
    }
    else if (icmp_type == ICMP_HOSTUNREACHABLE) {
      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 1;
    }
    else if (icmp_type == ICMP_PORTUNREACHABLE) {
      icmp_hdr->icmp_type = 3;
      icmp_hdr->icmp_code = 3;
    }
    else if (icmp_type == ICMP_TIMEEXCEEDED) {
      icmp_hdr->icmp_type = 11;
      icmp_hdr->icmp_code = 0;
    }
    else {
      printf("ERROR: unrecognized ICMP type. \n");
    }
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, original_ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
  }
}

/* Create and populate ICMP packet.*/
void icmp_handler (struct sr_instance* sr /* lent */,
                int icmp_type,
                uint8_t* original_packet /* lent */,
                int original_len,
                uint32_t sender_ip){

  sr_ip_hdr_t *original_ip_hdr = (sr_ip_hdr_t *)(original_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *lpm = LPM(original_ip_hdr->ip_src, sr->routing_table);
  if (!lpm) {
    printf("ERROR: no longest prefix match\n");
    return;
  }

  /* We need this sender IP arg for ICMP host unreachable; source IP of outgoing ICMP message
  * is the address of the interface that sent out the ARP requests (that had no response). If
  * not specified (for all other ICMP types), we use the default source IP (IP of interface
  * of next hop) */
  if (!sender_ip && icmp_type != ICMP_ECHOREPLY) {
    struct sr_if* out_if = sr_get_interface(sr, lpm->interface);
    sender_ip = out_if->ip;
  }

  if (icmp_type == ICMP_ECHOREPLY) { /* Type 0 header */
    /* Reusing original packet and modifying values */
    uint32_t ip_src = original_ip_hdr->ip_dst;
    original_ip_hdr->ip_dst = original_ip_hdr->ip_src;
    original_ip_hdr->ip_src = ip_src;
    original_ip_hdr->ip_ttl = INIT_TTL;
    original_ip_hdr->ip_sum = 0;
    original_ip_hdr->ip_sum = cksum(original_ip_hdr, original_ip_hdr->ip_hl * 4);
    populate_icmp_hdr(icmp_type, original_packet, original_packet);
    lookup_and_send(sr, original_packet, original_len, lpm);
  }
  else { /* Type 3 or type 11 header */
    int icmp_len = sizeof(sr_icmp_t3_hdr_t);
    int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len;
    uint8_t *new_packet = malloc(packet_len);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_packet;
    enum sr_ethertype ethertype = ethertype_ip;
    eth_hdr->ether_type = htons(ethertype);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

    enum sr_ip_protocol protocol = ip_protocol_icmp;

    populate_ip_hdr(ip_hdr, icmp_len, protocol, sender_ip, original_ip_hdr->ip_src);

    populate_icmp_hdr(icmp_type, new_packet, original_packet);

    lookup_and_send(sr, new_packet, packet_len, lpm);
    free(new_packet);
  }
}

/*--------------------------------------------------------------------
 * Forward an IP packet that is not destined for one of our interfaces.
 *--------------------------------------------------------------------*/
void forward_ip_packet(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int packet_len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  ip_hdr->ip_ttl--;
  if (ip_hdr->ip_ttl < 1) {
    printf("TTL of packet we have to forward is 0. Sending Time Exceeded ICMP.\n");
    icmp_handler(sr, ICMP_TIMEEXCEEDED, packet, 0, 0);
    return;
  }
  /* Recalculate checksum because we modified the ttl in the header */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

  struct sr_rt *lpm = LPM(ip_hdr->ip_dst, sr->routing_table);
  if (!lpm) {
    /*printf("Sending ICMP net unreachable.\n");*/
    icmp_handler(sr, ICMP_NETUNREACHABLE, packet, 0, 0);
    return;
  }

  lookup_and_send(sr, packet, packet_len, lpm);
}

void lookup_and_send(struct sr_instance* sr, uint8_t* packet, int packet_len, struct sr_rt* lpm) {

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

  struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), lpm->gw.s_addr);

  /* cache hit; grab MAC address (replaces old destination in ethernet header) and send the packet */
  if (arpentry) {
    struct sr_if* out_if = sr_get_interface(sr, lpm->interface);
    memcpy(eth_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    printf("DEBUG: SEND PACKET (2).\n");
    /*print_hdrs(packet, packet_len);*/
    sr_send_packet(sr, packet, packet_len, lpm->interface);
    free(arpentry);
  }
  /* cache miss; need an ARP request to grab MAC address */
  else {
    struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache), lpm->gw.s_addr, packet, packet_len, lpm->interface);
    handle_arpreq(sr, arpreq);
  }
}
