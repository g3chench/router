#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_icmp_handler.h"
#include "sr_utils.h"
#include "sr_arp_handler.h"

void arp_handler(struct sr_instance* sr,
                  uint8_t * packet,
                  unsigned int len,
                  char* interface) {

    printf("TESTING: IN ARP HANDLER\n");
    struct sr_if* sr_interface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    printf("HERE\n");


    if (!get_output_interface(sr->if_list, arp_hdr->ar_tip)) {
        printf("cannot find outputting interface\n");
        fprintf(stderr, "ERROR: ARP pkt not for us\n");
        return;
    }
    printf("Here 1\n");

    if (arp_hdr->ar_hrd != htons(arp_hrd_ethernet)){
        fprintf(stderr, "Invalid ARP hardware format\n");
        return;
    }

    printf("Here 2\n");
    printf("Passed Sanity Checks\nHandlng this ARP packet...\n");

    struct sr_arpreq* arp_req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

    switch (htons(arp_hdr->ar_op)) {
        /* If the packet is a request */
        case arp_op_request:
            printf("Passing to handle_arp_request\n");
            printf("Send an arp reply request\n");
            handle_arp_request(sr, packet, len, interface, sr_interface, arp_hdr, eth_hdr);
            break;

        /* If the packet is a reply */
        case arp_op_reply:
            printf("Passing to handle_arp_reply\n");
            handle_arp_reply(sr, packet, arp_req);
            break;

        default:
            /*fprintf(stderr, "Invalid Ethernet Type: %d\n", ntohs(eth_hdr->ether_type));*/
            fprintf(stderr, "Invalid Ethernet Type\n");
    }
}

/**
 * Send an ARP reply back when an ARP request is made.
 */
void handle_arp_request(struct sr_instance* sr,
                        uint8_t * packet,
                        unsigned int len,
                        char* interface,
                        struct sr_if* sr_interface,
                        sr_arp_hdr_t *arp_hdr,
                        sr_ethernet_hdr_t *eth_hdr) {
    printf("Incoming arp request\n");
    printf("IN FUNCTION: handle_arp_request-------------------\n");

    /* Construct an outgoing ethernet packet containing an ARP reply packet*/
    /* build the ethernet frame*/
    unsigned int reply_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* reply_pkt = malloc(reply_pkt_len);

    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *)packet;

    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_pkt;
    gen_eth_hdr(reply_eth_hdr, request_eth_hdr->ether_shost, sr_interface->addr, htons(ethertype_arp));
    
    /* Fill in the ARP reply header*/
    sr_arp_hdr_t *request_arp_hdr =((sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)));
    
    sr_arp_hdr_t *reply_arp_hdr = ((sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t)));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = arp_op_request;
    arp_hdr->ar_sip = sr_interface->addr;
    arp_hdr->ar_tip = sr_interface->ip;
    memcpy(reply_arp_hdr->ar_sha, request_arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_arp_hdr->ar_tha, request_arp_hdr->ar_sip, ETHER_ADDR_LEN);

    /* Send  packet (ethernet header included!) of length 'len'
    * to the server to be injected onto the wire.*/
    sr_send_packet(sr, reply_pkt, len, interface);
    free(reply_pkt);
}

void handle_arp_reply(struct sr_instance* sr, uint8_t* packet, struct sr_arpreq* arp_req) {

    printf("IN FUNCTION:handle_arp_reply-------------------\n");
    printf("Sending an ARP reply\n");

    sr_arp_hdr_t* old_arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_arpreq *req_entry = sr_arpcache_insert(&(sr->cache), old_arp_hdr->ar_sha, old_arp_hdr->ar_sip);

    struct sr_packet* curr_pkt = req_entry->packets;
    while (curr_pkt) {
        uint8_t *frame = curr_pkt->buf;
        sr_ethernet_hdr_t *frame_eth_hdr = (sr_ethernet_hdr_t *) frame;
        
        sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *) curr_pkt->buf;
        struct sr_if *if_out = sr_get_interface(sr, curr_pkt->iface);
        
        gen_eth_hdr(etherhdr, old_arp_hdr->ar_sha, if_out->addr, ethertype_arp);
        print_hdr_eth(etherhdr);

        sr_send_packet(sr, curr_pkt->buf, curr_pkt->len, curr_pkt->iface);
        curr_pkt = curr_pkt->next;
    }

    sr_arpreq_destroy(&(sr->cache), arp_req);
}