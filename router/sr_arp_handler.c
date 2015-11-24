#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
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
    
    if (!get_output_interface(arp_hdr->ar_tip, sr->if_list)) {
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
    
    struct sr_arpreq* arpReq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

    switch (htons(arp_hdr->ar_op)){
        /* If the packet is a request */
        case arp_op_request:
            printf("Passing to handle_arp_request\n");
            printf("Send an arp reply request\n");
            handle_arp_request(sr, packet, len, interface, sr_interface, arp_hdr, eth_hdr);
            break;

        /* If the packet is a reply */
        case arp_op_reply:
            printf("Passing to handle_arp_reply\n");
            handle_arp_reply(sr, arpReq);
            break;

        default:
            fprintf(stderr, "Invalid Ethernet Type: %d\n", ntohs(eth_hdr->ether_type));
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
    printf("TESTING: IN ARP HANDLE REQUEST\n");

    /* Construct an outgoing ethernet packet containing an ARP reply packet*/
    /* build the ethernet frame*/
    unsigned int reply_pkt_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* reply_pkt = malloc(reply_pkt_len);
    
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_pkt;

    /* Fill in the ethernet reply header*/    
    memcpy(reply_eth_hdr->ether_dhost, request_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    /* Fill in the ARP reply header*/
    sr_arp_hdr_t *request_arp_hdr = ((sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t)));
    sr_arp_hdr_t *reply_arp_hdr = ((sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)));

    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(arp_op_reply);
    arp_hdr->ar_sip = sr_interface->addr;
    arp_hdr->ar_tip = sr_interface->ip;
    memcpy(reply_arp_hdr->ar_sha, request_arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_arp_hdr->ar_tha, request_arp_hdr->ar_sip, ETHER_ADDR_LEN);

    /* encapsulate ARP header in ethernet header*/
    reply_pkt = (uint8_t*)reply_eth_hdr;    
    
    /* Send  packet (ethernet header included!) of length 'len'
    * to the server to be injected onto the wire.*/
    sr_send_packet(sr, reply_pkt, len, interface);

    free(reply_pkt);
}

void handle_arp_reply(struct sr_instance* sr,
                    struct sr_arpreq* arpReq) {
    printf("Sending an ARP reply\n");
    printf("TESTING: IN handle_arp_reply\n");
    if (arpReq) {
        struct sr_packet* currPkt = arpReq->packets;
        while (currPkt) {
            sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *) currPkt->buf;
/*            sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(currPkt + sizeof(sr_ethernet_hdr_t));
            memcpy(etherhdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
*/
            struct sr_if *if_out = sr_get_interface(sr, currPkt->iface);
            memcpy(etherhdr->ether_shost, if_out->addr, ETHER_ADDR_LEN);
            memcpy(etherhdr->ether_dhost, etherhdr->ether_shost, ETHER_ADDR_LEN);

            printf("ethernet source: %u\n", *etherhdr->ether_shost);
            printf("ethernet destination: %u\n", *etherhdr->ether_dhost);
            


            sr_send_packet(sr, currPkt->buf, currPkt->len, currPkt->iface);
            currPkt = currPkt->next;
        }
        sr_arpreq_destroy(&sr->cache, arpReq);
    }
}