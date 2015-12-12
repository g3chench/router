#ifndef SR_ICMP_H
#define SR_ICMP_H

#define ECHO_REPLY       0
#define NET_UNREACHABLE  30
#define HOST_UNREACHABLE 31
#define PORT_UNREACHABLE 33
#define TIME_EXCEEDED    110

void handle_ICMP(struct sr_instance* sr, int icmp_type, uint8_t* pkt, int len, uint32_t ip_sip);

void icmp_hdr_filter(uint8_t *buf, uint8_t *pkt, int icmp_type);

void sr_arp_entry_filter(struct sr_instance* sr, uint8_t* pkt, int len, struct sr_rt* rt);

#endif