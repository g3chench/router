#ifndef SR_IP_HANDLER_H
#define SR_IP_HANDLER_H

struct sr_if *get_output_interface(struct sr_instance *sr, uint32_t address);

struct sr_rt* lpm(struct sr_instance* sr, uint8_t* packet, struct sr_if* in_interface, sr_ip_hdr_t* ip_hdr);

struct sr_arpentry* search_arpcache(struct sr_instance* sr, uint8_t* packet, struct sr_rt* matching_entry);

void ip_handler(struct sr_instance* sr, uint8_t* packet, unsigned int len, char *interface);

#endif
