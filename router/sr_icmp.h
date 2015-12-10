#ifndef SR_ICMP_H
#define SR_ICMP_H

#define ECHO_REPLY       0
#define NET_UNREACHABLE  30
#define HOST_UNREACHABLE 31
#define PORT_UNREACHABLE 33
#define TIME_EXCEEDED    110

void handle_ICMP (struct sr_instance* sr, int type, uint8_t* old_packet, int old_len, uint32_t sender_ip);

void gen_icmp_hdr(int type, uint8_t *buf, uint8_t *old_packet);

void gen_ip_hdr(struct sr_ip_hdr *ip_hdr, uint16_t len, uint8_t protocol, uint32_t src, uint32_t dst);

void gen_eth_hdr(struct sr_ethernet_hdr *eth_hdr, uint8_t dest[ETHER_ADDR_LEN], uint8_t src[ETHER_ADDR_LEN], uint16_t type);

#endif