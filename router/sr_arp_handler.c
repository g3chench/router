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
                  char* interface,
                  unsigned int minLen,
                  uint16_t frame){
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* Add ARP Header length to minLen with Ethernet header length */
    minLen += sizeof(sr_arp_hdr_t);

    /* if packet size is smaller than the total minimum length
    of ARP Header and Ethernet Header combined, then output error*/
    if (minLen > len){
        fprintf(stderr, "ARP Header length is too large\n");
    } else if (arpHeader->ar_hrd != htons(arp_hrd_ethernet)){
        /* If ARP packet format is incorrect, then output error */
        fprintf(stderr, "Invalid ARP hardware format\n");
    } else {
        if (ntohs(arpHeader->ar_hrd) == arp_hrd_ethernet &&
        arpHeader->ar_hln == 0x06 &&
        arpHeader->ar_pln == 0x04 &&
        ntohs (arpHeader->ar_pro) == ethertype_ip){
            struct sr_if* sr_interface = sr_get_interface(sr, interface);
            sr_ethernet_hdr_t *etherHeader = (sr_ethernet_hdr_t *)packet;
            struct sr_arpreq* arpReq = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);

            switch (ntohs(arpHeader->ar_op)){
            /* If the packet is a request */
            case arp_op_request:
                handle_arp_request(sr, packet, len, interface, sr_interface, arpHeader, etherHeader);
            break;

            /* If the packet is a reply */
            case arp_op_reply:
                handle_arp_reply(sr, arpReq);
                break;
            default:
                fprintf(stderr, "Invalid Ethernet Type: %d\n", frame);
            }
        }
    }

}

void handle_arp_request(struct sr_instance* sr,
                        uint8_t * packet,
                        unsigned int len,
                        char* interface,
                        struct sr_if* sr_interface,
                        sr_arp_hdr_t *arpHeader,
                        sr_ethernet_hdr_t *etherHeader) {
    if (ntohl(sr_interface->ip) == ntohl(arpHeader->ar_tip)){
        memcpy(etherHeader->ether_dhost, etherHeader->ether_shost, ETHER_ADDR_LEN);
        memcpy(etherHeader->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);

        arpHeader->ar_op = htons(arp_op_reply);
        arpHeader->ar_tip = arpHeader->ar_sip;
        arpHeader->ar_sip = sr_interface->ip;

        memcpy(arpHeader->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
        memcpy(arpHeader->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
        /* Send  packet (ethernet header included!) of length 'len'
        * to the server to be injected onto the wire.*/
        sr_send_packet(sr, packet, len, interface);
    }
}

void handle_arp_reply(struct sr_instance* sr,
                    struct sr_arpreq* arpReq) {
    if (arpReq) {
        struct sr_packet* currPkt = arpReq->packets;
        while (currPkt) {
            sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *) currPkt->buf;
            sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t *)(currPkt + sizeof(sr_ethernet_hdr_t));

            memcpy(etherhdr->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
            memcpy(etherhdr->ether_shost, arpHeader->ar_tha, ETHER_ADDR_LEN);

            sr_send_packet(sr, currPkt->buf, currPkt->len, currPkt->iface);
            currPkt = currPkt->next;
        }
        sr_arpreq_destroy(&sr->cache, arpReq);
    }
}