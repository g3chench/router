#ifndef SR_IP_HANDLER_H
#define SR_IP_HANDLER_H

struct sr_if *get_output_interface(struct sr_instance* sr, uint32_t address);

void ip_handler(struct sr_instance* sr, struct sr_packet *packet, unsigned int len, struct sr_if *interface);

#endif
