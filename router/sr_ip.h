#ifndef SR_IP_H
#define SR_IP_H

void handle_IP (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);

struct sr_if* sr_get_if_from_ip(uint32_t ip_addr, struct sr_if* iface);

struct sr_rt* lpm(uint32_t ip_addr, struct sr_rt *rtable);

void forward_ip_pkt(struct sr_instance* sr, uint8_t * packet, unsigned int len);

#endif /* -- SR_IP_H -- */