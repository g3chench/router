#ifndef SR_ARP_HANDLER_H
#define SR_ARP_HANDLER_H

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

void arp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, unsigned int minLen, uint16_t frame);

void handle_arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, struct sr_if* sr_interface, sr_arp_hdr_t *arpHeader, sr_ethernet_hdr_t *etherHeader);

void handle_arp_reply(struct sr_instance* sr, struct sr_arpreq* arpReq);

#endif
