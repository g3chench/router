#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

void send_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
	int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *packet = malloc(packet_len);

	struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *)packet;
	struct sr_if *if_out = sr_get_interface(sr, req->packets->iface);
	uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	enum sr_ethertype eth_type;
	enum sr_ethertype arp_type;
	eth_type = ethertype_arp;
	arp_type = ethertype_ip;
	populate_eth_hdr(ethernet_header, broadcast_addr, if_out->addr, eth_type);

	struct sr_arp_hdr *arp_header = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
	enum sr_arp_hrd_fmt arp_hdr_fmt;
	arp_hdr_fmt = arp_hrd_ethernet;
	enum sr_arp_opcode opcode;
	opcode = arp_op_request;
	populate_arp_hdr(arp_header, 
					arp_hdr_fmt, 
					arp_type, 
					ETHER_ADDR_LEN, 
					4, 
					opcode, 
					if_out->addr,
					if_out->ip, 
					broadcast_addr,
					req->ip);

	printf("DEBUG: SEND PACKET (3).\n");
	/*print_hdrs(packet, packet_len);*/

	sr_send_packet(sr, packet, packet_len, if_out->name);
	free(packet);
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
	time_t curtime = time(NULL);
	if (difftime(curtime, req->sent) >= 0.9) {
		/* Send ICMP host unreachable to all waiting packets */
		if (req->times_sent >= 5) {
			struct sr_packet *waiting_packet = req->packets; /* linked list */
			struct sr_if *if_out = sr_get_interface(sr, waiting_packet->iface);
			while (waiting_packet) {
				handle_ICMP(sr, ICMP_HOSTUNREACHABLE, waiting_packet->buf, 0, if_out->ip);
				waiting_packet = waiting_packet->next;
			}
			sr_arpreq_destroy(&(sr->cache), req);
		}
		else {
			send_arpreq(sr, req);
			req->sent = curtime;
			req->times_sent++;
		}
	}
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
	struct sr_arpreq *request = sr->cache.requests; /* linked list of requests */
	while (request) {
		/* Store next request because handle_arpreq may destroy current one */
		struct sr_arpreq *next_request = request->next;
		handle_arpreq(sr, request);
		request = next_request;
	}
}

/*
 * Pass in the ARP Header to be populated
 * with it's corresponding params
 */
void populate_arp_hdr(sr_arp_hdr_t * arp_hdr,
					  unsigned short  ar_hrd,
					  unsigned short  ar_pro,
					  unsigned char   ar_hln,
					  unsigned char   ar_pln,
					  unsigned short  ar_op,
					  unsigned char*  ar_sha,
					  uint32_t        ar_sip,
					  unsigned char*  ar_tha,
					  uint32_t        ar_tip) {

	/* format of hardware address   */
	arp_hdr->ar_hrd = htons(ar_hrd);
	/* format of protocol address   */
	arp_hdr->ar_pro = htons(ar_pro);
	/* length of hardware address   */
	arp_hdr->ar_hln = ar_hln;
	/* length of protocol address   */
	arp_hdr->ar_pln = ar_pln;
	/* ARP opcode (command)         */
	arp_hdr->ar_op = htons(ar_op);
	/* sender IP address            */
	arp_hdr->ar_sip = ar_sip;
	/* target IP address            */
	arp_hdr->ar_tip = ar_tip;
	/* sender hardware address      */
	memcpy(arp_hdr->ar_sha, ar_sha, ETHER_ADDR_LEN);
	/* target hardware address      */
	memcpy(arp_hdr->ar_tha, ar_tha, ETHER_ADDR_LEN);
}

/*
 * Contains Logic to Handle ARP Request
 * Create New Ethernet Header
 * Create New ARP Header
 * Sends the packet back to source
 */
void respond_to_arpreq (struct sr_instance* sr,
						 uint8_t * req_packet/* lent */,
						 unsigned int len,
						 struct sr_if* inf)
{
	unsigned int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *reply_packet = malloc(packet_len);

	struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)reply_packet;
	struct sr_ethernet_hdr *req_eth_hdr = (struct sr_ethernet_hdr *)req_packet;

	enum sr_ethertype eth_type;
	enum sr_ethertype arp_type;
	eth_type = ethertype_arp;
	arp_type = ethertype_ip;
	enum sr_arp_hrd_fmt arp_hdr_fmt;
	arp_hdr_fmt = arp_hrd_ethernet;
	enum sr_arp_opcode opcode;
	opcode = arp_op_reply;

	populate_eth_hdr(eth_hdr,
					req_eth_hdr->ether_shost, /* Ethernet Destination is Received Ethernets Source */
					inf->addr,            /* Ethernet Source is Current Interface Address */
					eth_type);

	/* Create Reply ARP Header
	 * Reply Source is Current Interface IP
	 * Reply Destination is Received ARP's Source */
	struct sr_arp_hdr *arp_hdr = ((struct sr_arp_hdr *)(reply_packet + sizeof(sr_ethernet_hdr_t)));
	struct sr_arp_hdr *req_arp_hdr = ((struct sr_arp_hdr *)(req_packet + sizeof(sr_ethernet_hdr_t)));
	populate_arp_hdr(arp_hdr,
					 arp_hdr_fmt,
					 arp_type,
					 ETHER_ADDR_LEN,
					 4,
					 opcode,
					 inf->addr,       /* Source Addr: Current Interface */
					 inf->ip,         /* Source IP: Current Interface */
					 req_arp_hdr->ar_sha, /* Dest Addr: Send Back to ARP Source */
					 req_arp_hdr->ar_sip);/* Dest IP: Send Back to ARP Source */

	/*printf("DEBUG: PRINTING OUT ALL REPLY PACKET INFO\n");*/
	/*print_hdrs(reply_packet, packet_len);*/

	/* Send a reply */
	sr_send_packet(sr, reply_packet, packet_len, inf->name);

	/* Free after Packet is Sent */
	free(reply_packet);
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
	pthread_mutex_lock(&(cache->lock));
	
	struct sr_arpentry *entry = NULL, *copy = NULL;
	
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
			entry = &(cache->entries[i]);
		}
	}
	
	/* Must return a copy b/c another thread could jump in and modify
	   table after we return. */
	if (entry) {
		copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
		memcpy(copy, entry, sizeof(struct sr_arpentry));
	}
		
	pthread_mutex_unlock(&(cache->lock));
	
	return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
									   uint32_t ip,
									   uint8_t *packet,           /* borrowed */
									   unsigned int packet_len,
									   char *iface)
{
	pthread_mutex_lock(&(cache->lock));
	
	struct sr_arpreq *req;
	for (req = cache->requests; req != NULL; req = req->next) {
		if (req->ip == ip) {
			break;
		}
	}
	
	/* If the IP wasn't found, add it */
	if (!req) {
		req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
		req->ip = ip;
		req->next = cache->requests;
		cache->requests = req;
	}
	
	/* Add the packet to the list of packets for this request */
	if (packet && packet_len && iface) {
		struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
		
		new_pkt->buf = (uint8_t *)malloc(packet_len);
		memcpy(new_pkt->buf, packet, packet_len);
		new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
		strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
		new_pkt->next = req->packets;
		req->packets = new_pkt;
	}
	
	pthread_mutex_unlock(&(cache->lock));
	
	return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
	  to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
									 unsigned char *mac,
									 uint32_t ip)
{
	pthread_mutex_lock(&(cache->lock));
	
	struct sr_arpreq *req, *prev = NULL, *next = NULL; 
	for (req = cache->requests; req != NULL; req = req->next) {
		if (req->ip == ip) {            
			if (prev) {
				next = req->next;
				prev->next = next;
			} 
			else {
				next = req->next;
				cache->requests = next;
			}
			
			break;
		}
		prev = req;
	}
	
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		if (!(cache->entries[i].valid))
			break;
	}
	
	if (i != SR_ARPCACHE_SZ) {
		memcpy(cache->entries[i].mac, mac, 6);
		cache->entries[i].ip = ip;
		cache->entries[i].added = time(NULL);
		cache->entries[i].valid = 1;
	}
	
	pthread_mutex_unlock(&(cache->lock));
	
	return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
	pthread_mutex_lock(&(cache->lock));
	
	if (entry) {
		struct sr_arpreq *req, *prev = NULL, *next = NULL; 
		for (req = cache->requests; req != NULL; req = req->next) {
			if (req == entry) {                
				if (prev) {
					next = req->next;
					prev->next = next;
				} 
				else {
					next = req->next;
					cache->requests = next;
				}
				
				break;
			}
			prev = req;
		}
		
		struct sr_packet *pkt, *nxt;
		
		for (pkt = entry->packets; pkt; pkt = nxt) {
			nxt = pkt->next;
			if (pkt->buf)
				free(pkt->buf);
			if (pkt->iface)
				free(pkt->iface);
			free(pkt);
		}
		
		free(entry);
	}
	
	pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
	fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
	fprintf(stderr, "-----------------------------------------------------------\n");
	
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		struct sr_arpentry *cur = &(cache->entries[i]);
		unsigned char *mac = cur->mac;
		fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
	}
	
	fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
	/* Seed RNG to kick out a random entry if all entries full. */
	srand(time(NULL));
	
	/* Invalidate all entries */
	memset(cache->entries, 0, sizeof(cache->entries));
	cache->requests = NULL;
	
	/* Acquire mutex lock */
	pthread_mutexattr_init(&(cache->attr));
	pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
	
	return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
	return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
	struct sr_instance *sr = sr_ptr;
	struct sr_arpcache *cache = &(sr->cache);
	
	while (1) {
		sleep(1.0);
		
		pthread_mutex_lock(&(cache->lock));
	
		time_t curtime = time(NULL);
		
		int i;    
		for (i = 0; i < SR_ARPCACHE_SZ; i++) {
			if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
				cache->entries[i].valid = 0;
			}
		}
		
		sr_arpcache_sweepreqs(sr);

		pthread_mutex_unlock(&(cache->lock));
	}
	
	return NULL;
}

