#ifndef SR_IP_H
#define SR_IP_H

struct sr_if* sr_get_if_from_ip(uint32_t ip_addr, struct sr_if* iface);

struct sr_rt* lpm(uint32_t ip_addr, struct sr_rt *rtable);

void forward_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len);

#endif /* -- SR_IP_H -- */