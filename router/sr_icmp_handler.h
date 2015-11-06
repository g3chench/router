#ifndef SR_ICMP_HANDLER_H
#define SR_ICMP_HANDLER_H

sr_icmp_hdr_t *gen_icmp_packet (int type, int code);

uint8_t* gen_eth_frame (uint8_t *packet, uint8_t *icmp_pkt, struct sr_if *interface);

void send_icmp_echo_reply(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

void send_icmp_echo_request(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

void send_icmp_host_unreachable(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

void send_icmp_time_exceeded(struct sr_instance *sr, uint8_t* packet, struct sr_if *interface);

#endif
