/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* sr, uint8_t* buf, unsigned int len, const char* iface);
int sr_connect_to_server(struct sr_instance* sr,unsigned short port, char* server);
int sr_read_from_server(struct sr_instance* sr);

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sr_arp_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, unsigned int minLen, uint16_t frame);
void handle_arp_request(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, struct sr_if* sr_interface, sr_arp_hdr_t *arpHeader, sr_ethernet_hdr_t *etherHeader);
void handle_arp_reply(struct sr_instance* sr, struct sr_arpreq* arpReq);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* sr, const char* name);
void sr_set_ether_ip(struct sr_instance* sr, uint32_t ip_nbo);
void sr_set_ether_addr(struct sr_instance* sr, const unsigned char* addr);
void sr_print_if_list(struct sr_instance* sr);

#endif /* SR_ROUTER_H */
