#ifndef SR_ICMP_HANDLER_H
#define SR_ICMP_HANDLER_H

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

sr_icmp_hdr_t gen_icmp_packet (int type, int code, uint8_t cargo_len);

sr_ethernet_hdr_t* gen_eth_frame (sr_ethernet_hdr_t *old_eth_pkt, int old_len, uint8_t *icmp_pkt, int icmp_type);

void send_icmp_echo_request(struct sr_instance *sr, struct sr_packet *packet, struct sr_if *interface);

void send_icmp_net_unreachable(struct sr_instance *sr, struct sr_packet *packet, struct sr_if *interface);

void send_icmp_host_unreachable(struct sr_instance *sr, struct sr_packet *packet, struct sr_if *interface);

void send_icmp_port_unreachable(struct sr_instance *sr, struct sr_packet *packet, struct sr_if *interface);

void send_icmp_time_exceeded(struct sr_instance *sr, struct sr_packet *packet, struct sr_if *interface);

#endif
