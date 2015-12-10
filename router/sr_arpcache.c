#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"
#include "sr_icmp.h"
#include "sr_arpcache.h"



void handle_ARP(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	printf("In handle_ARP()---------------\n");
	
	struct sr_if *inf = sr_get_interface(sr, interface);
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	if (!get_iface(arp_hdr->ar_tip, sr)) {
		fprintf(stderr, "ERROR: This ARP packet is not for us\n");
		return;
	}

	if (arp_hdr->ar_op == htons(arp_op_request)) {
		printf("	got an arp op_request\n");
		handle_op_request(sr, packet, len, inf);
	}
	else if (arp_hdr->ar_op == htons(arp_op_reply)) {
		printf("	got an op_reply\n");
		handle_op_reply(sr, arp_hdr);

	} else {
		fprintf(stderr, "ERROR: invalid ARP type specified\n");
	}
} /*end of handle_ARP() */


/**
 * Send an ARP request given an ARP reply.
 * @param sr      sr instance
 * @param arp_hdr arp header containing the arp reply
 */
void handle_op_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr) {
	printf("	In handle_op_reply() ----------------\n");

	struct sr_arpreq *req_entry = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
	printf("	Loop through list of recent packets that replied to us and send arp reply for each...\n");
	
	/* Loop through packet we recieved an ARP request from and reply to each with an
	ARP reply packet. */
	struct sr_packet *current_packet = req_entry->packets;
	while (current_packet) {
		printf("		Constructing arp request packet..\n");
		uint8_t *reply_pkt = current_packet->buf;
		
		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) reply_pkt;
		struct sr_if *out_iface = sr_get_interface(sr, current_packet->iface);
		memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
		memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
		
		printf("		sending arp request packet...\n");
		sr_send_packet(sr, reply_pkt, current_packet->len, current_packet->iface);
		
		current_packet = current_packet->next;
	}
	
	/*Remove the arp request after sending a reply to it*/
	sr_arpreq_destroy(&(sr->cache), req_entry);
}



/**
 * Send an arp request packet
 * @param sr  sr instance
 * @param request ARP request packet received
 */
void send_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {
	printf("	in send_arpreq() ------------\n");

	/*Construct arp request packet*/
	int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *packet = malloc(packet_len);

	struct sr_ethernet_hdr *ethernet_header = (struct sr_ethernet_hdr *)packet;
	struct sr_if *out_iface = sr_get_interface(sr, request->packets->iface);
	
	uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	gen_eth_hdr(ethernet_header, broadcast_addr, out_iface->addr, ethertype_arp);

	struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

	gen_arp_hdr(arp_hdr, 
					arp_hrd_ethernet, 
					ethertype_ip, 
					ETHER_ADDR_LEN, 
					4, 
					arp_op_request, 
					out_iface->addr,
					out_iface->ip, 
					broadcast_addr,
					request->ip);

	/*send ARP request pkt thru outgoing interface*/
	sr_send_packet(sr, packet, packet_len, out_iface->name);
	free(packet);
}



/* After 1.0 second of sending the given arp request, check if this
* request was already sent 5 times. If it ha, send ICMP host unreachable
* message to packets waiting for a reply in a linked list. 
* Do not attempt to send this request again otherwise...
*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
	printf("	In handle_arpreq()------------------\n");
	time_t curtime = time(NULL);

	if (difftime(curtime, req->sent) >= 1.0) {
		if (req->times_sent >= 5) {
			printf("This packet was sent 5 times already. Send ICMP HOST_UNREACHABLE \n");
			struct sr_packet *waiting_pkts = req->packets;
			struct sr_if *out_iface = sr_get_interface(sr, waiting_pkts->iface);

			while (waiting_pkts) {
				handle_ICMP(sr, HOST_UNREACHABLE, waiting_pkts->buf, 0, out_iface->ip);
				waiting_pkts = waiting_pkts->next;
			}
			sr_arpreq_destroy(&(sr->cache), req);

		/* Otherwise, send an ARP request */
		} else {
			send_arpreq(sr, req);
			req->sent = curtime;
			req->times_sent++;
		}
	}
}



/**
 * Fill in an arp header given its pointer. 
 * @param arp_hdr      pointer to arp header to fill in
 * @param hw_fmt       hardware address format
 * @param protocol     ARP protocol type
 * @param hw_len       hardware address length
 * @param protocol_len protocol length
 * @param opcode       ARP opcode type
 * @param sha          sender's hardware address
 * @param sip          sender's IP address
 * @param tha          target's hardware address
 * @param tip          target's IP address
 */
void gen_arp_hdr(sr_arp_hdr_t * arp_hdr,
			  unsigned short  hw_fmt,
			  unsigned short  protocol,
			  unsigned char   hw_len,
			  unsigned char   protocol_len,
			  unsigned short  opcode,
			  unsigned char*  sha,
			  uint32_t        sip,
			  unsigned char*  tha,
			  uint32_t        tip) {

	printf("	in gen_arp_hdr()------------\n");

	arp_hdr->ar_hrd = htons(hw_fmt);
	arp_hdr->ar_pro = htons(protocol);
	arp_hdr->ar_hln = hw_len;
	arp_hdr->ar_pln = protocol_len;
	arp_hdr->ar_op = htons(opcode);
	arp_hdr->ar_sip = sip;
	arp_hdr->ar_tip = tip;
	memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
	memcpy(arp_hdr->ar_tha, tha, ETHER_ADDR_LEN);
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



/**
 * Respond to an ARP op request by constructing an ARP reply to send back
 * to to the sender through a given outgoing interface.
 *
 * @param sr          sr instance
 * @param request_pkt incoming ARP request packet
 * @param len         length of ARP request packet
 * @param iface       interface this request packet was sent through
 */
void handle_op_request (struct sr_instance* sr,
						 uint8_t * request_pkt, 
						 unsigned int len,
						 struct sr_if* iface) {

	/* Contruct arp reply packet to send back to the source address and IP. */
	unsigned int reply_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *reply_pkt = malloc(reply_pkt_len);

	struct sr_ethernet_hdr *request_eth_hdr = (struct sr_ethernet_hdr *)request_pkt;
	struct sr_ethernet_hdr *reply_arp_hdr = (struct sr_ethernet_hdr *)reply_pkt;

	gen_eth_hdr(reply_arp_hdr,
					request_eth_hdr->ether_shost, 
					iface->addr, 
					ethertype_arp);

	struct sr_arp_hdr *arp_hdr = ((struct sr_arp_hdr *)(reply_pkt + sizeof(sr_ethernet_hdr_t)));
	struct sr_arp_hdr *request_arp_hdr = ((struct sr_arp_hdr *)(request_pkt + sizeof(sr_ethernet_hdr_t)));
	gen_arp_hdr(arp_hdr,
			arp_hrd_ethernet,
			ethertype_ip,
			ETHER_ADDR_LEN,
			4,
			arp_op_reply,
			iface->addr, 
			iface->ip,
			request_arp_hdr->ar_sha, 
			request_arp_hdr->ar_sip);

	sr_send_packet(sr, reply_pkt, reply_pkt_len, iface->name);

	free(reply_pkt);
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

