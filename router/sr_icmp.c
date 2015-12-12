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


void handle_ICMP(struct sr_instance* sr,
                 int icmp_type,
                 uint8_t* pkt,
                 int len,
                 uint32_t ip_sip) {

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *rt = lpm(ip_hdr->ip_src, sr->routing_table);
  if (!rt) {
    printf("ERROR: no longest prefix match\n");
    return;
  }


  if (!ip_sip && icmp_type != ECHO_REPLY) {
    struct sr_if* interface = sr_get_interface(sr, rt->interface);
    ip_sip = interface->ip;
  }

  if (icmp_type == ECHO_REPLY) { 
    uint32_t ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_src;
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
    icmp_hdr_filter(pkt, pkt, icmp_type);
    sr_arp_entry_filter(sr, pkt, len, rt);
  }
  else {
    uint8_t *new_pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_pkt;
    enum sr_ethertype ethertype = ethertype_ip;
    eth_hdr->ether_type = htons(ethertype);

    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));

    enum sr_ip_protocol protocol = ip_protocol_icmp;
    new_ip_hdr->ip_v = 4;             /* version */
    new_ip_hdr->ip_hl = 5;            /* header length */
    new_ip_hdr->ip_tos = 0;           /* type of service */
    new_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(sr_icmp_t3_hdr_t));  /* total length */
    new_ip_hdr->ip_id = 0x0000;       /* identification */
    new_ip_hdr->ip_off = htons(IP_DF);  /* fragment offset field */
    new_ip_hdr->ip_ttl = INIT_TTL;    /* time to live */
    new_ip_hdr->ip_p = protocol;      /* protocol */
    new_ip_hdr->ip_src = ip_sip;   /* source address*/
    new_ip_hdr->ip_dst = ip_hdr->ip_src; /* dest address*/

    
    new_ip_hdr->ip_sum = 0x0000; 
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

    icmp_hdr_filter(new_pkt, pkt, icmp_type);

    sr_arp_entry_filter(sr, new_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), rt);
    free(new_pkt);
  }
}

void icmp_hdr_filter(uint8_t *buf, uint8_t *pkt, int icmp_type) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));  
  sr_ip_hdr_t *buf_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  if (icmp_type == ECHO_REPLY) { 
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(sizeof(sr_ethernet_hdr_t) + buf + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(buf_ip_hdr->ip_len) - (buf_ip_hdr->ip_hl * 4));
  }
  else {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    switch(icmp_type){
      case PORT_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 3;
        break;
      case NET_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 0;
        break;
      case HOST_UNREACHABLE:
        icmp_hdr->icmp_type = 3;
        icmp_hdr->icmp_code = 1;
        break;
      case TIME_EXCEEDED:
        icmp_hdr->icmp_type = 11;
        icmp_hdr->icmp_code = 0;
        break;
      default:
        printf("ERROR: Invalid ICMP Type.\n");
        break;
    }

    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(buf_ip_hdr->ip_len) - (buf_ip_hdr->ip_hl * 4));
  }
}

void sr_arp_entry_filter(struct sr_instance* sr, uint8_t* pkt, int len, struct sr_rt* rt) {

  struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), rt->gw.s_addr);
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt;

  if (arpentry) {
    struct sr_if* interface = sr_get_interface(sr, rt->interface);
    memcpy(eth_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    printf("Sending Packets.. [2].\n");
    sr_send_packet(sr, pkt, len, rt->interface);
    free(arpentry);
  }
  else {
    handle_arpreq(sr, sr_arpcache_queuereq(&(sr->cache), rt->gw.s_addr, pkt, len, rt->interface));
  }
}
