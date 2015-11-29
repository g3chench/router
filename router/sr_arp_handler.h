#ifndef SR_ARP_HANDLER_H
#define SR_ARP_HANDLER_H

void arp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

void handle_arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, struct sr_if* sr_interface, sr_arp_hdr_t *arp_hdr, sr_ethernet_hdr_t *eth_hdr);

void handle_arp_reply(struct sr_instance* sr, uint8_t* packet, struct sr_arpreq* arp_req) {

#endif