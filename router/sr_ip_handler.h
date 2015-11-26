#ifndef SR_IP_HANDLER_H
#define SR_IP_HANDLER_H

struct sr_rt* lpm(struct sr_rt* routing_table, uint32_t ip_addr);

void cached_send(struct sr_instance* sr, uint8_t* packet, int len, struct sr_rt* matching_entry);

void ip_handler(struct sr_instance* sr, uint8_t* packet, unsigned int len, char *interface);

#endif
