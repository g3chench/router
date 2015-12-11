#ifndef SR_IP_H
#define SR_IP_H

void handle_IP (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

void forward_IP_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len);

struct sr_if* get_iface(uint32_t ip_addr, struct sr_instance *sr);

struct sr_rt* lpm(uint32_t ip_addr, struct sr_rt *rtable);

#endif /* -- SR_IP_H -- */