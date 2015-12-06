#ifndef SR_ICMP_HANDLER_H
#define SR_ICMP_HANDLER_H


void handle_icmp(int type, int code, struct sr_instance* sr, uint8_t* old_pkt, uint32_t sender, struct sr_if* iface);

void send_icmp_echo_reply(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void send_icmp_echo_request(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void send_icmp_net_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void send_icmp_host_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void send_icmp_port_unreachable(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void send_icmp_time_exceeded(struct sr_instance* sr, uint8_t *packet, uint8_t* sender, struct sr_if *interface);

void cached_send(struct sr_instance* sr, uint8_t* packet, int len, struct sr_rt* matching_entry);

void gen_icmp_hdr (uint8_t* destination, int type, int code, uint8_t *buffer);

void gen_ip_hdr(sr_ip_hdr_t* destination, uint32_t src, uint32_t dst, uint16_t cargo_size, uint8_t protocol);

void gen_eth_hdr(sr_ethernet_hdr_t* destination, uint8_t src[ETHER_ADDR_LEN], uint8_t dest[ETHER_ADDR_LEN], uint16_t type);

struct sr_rt* lpm(struct sr_rt* routing_table, uint32_t ip_addr);

#endif