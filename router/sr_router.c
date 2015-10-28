/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/


void sr_arp_handler(struct sr_instance* sr,
                  uint8_t * packet,
                  unsigned int len,
                  char* interface,
                  unsigned int minLen){
    minLen += sizeof(sr_arp_hdr_t);
    sr_arp_hdr_t *arpHeader = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    if (minLen > len){
        frpint(strderr, "Invalid ARP header length\n");
    } else if (arpHeader->ar_hrd != htons(arp_hrd_ethernet)){
        fprint(strderr, "Invalid ARP hardware format\n")
    } else {
        //To check ARP Packets, just run print_hdrs(packet, len)
        //define ARP header

        if (ntohs(arpHeader->ar_hrd) == arp_hrd_ethernet &&
        arpHeader->ar_hln == 0x06 &&
        arpHeader->ar_pln == 0x04 &&
        ntohs (arpHeader->ar_pro) == ethertype_ip){

            switch (ntohs(arpHeader->ar_op)){
            case arp_op_request:
                struct sr_if* sr_interface;
                sr_ethernet_hdr_t* etherHeader = (sr_ethernet_hdr_t*)packet;
                if (ntohl(struct sr_if* sr_interface->ip) == nothl(arpHeader->ar_tip)){
                    memcpy(etherHeader->ether_dhost, etherHeader->ether_shost, ETHER_ADDR_LEN);
                    memcpy(etherHeader->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);

                    arpHeader->ar_op = htons(arp_op_reply);
                    arpHeader->ar_tip = arpHeader->ar_sip;
                    arpHeader->ar_sip = sr_interface->ip;

                    memcpy(arpHeader->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
                    memcpy(arpHeader->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);

                    sr_send_packet(sr, packet, len, interface);
                }
            break;

            case arp_op_reply:
                struct sr_arpreq *arpReq = sr_arpcache_insert(&sr->cache, arpHeader->ar_sha, arpHeader->ar_sip);
                struct sr_if* sr_interface;
                if (arpReq){
                    struct sr_packet* currPkt = arpReq->packets;
                    while(currPkt){
                        sr_interface = sr_get_interface(sr, interface);
                        sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *) currPkt->buf;

                        memcpy(etherhdr->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN);
                        memcpy(etherhdr->ether_shost, arpHeader->ar_tha, ETHER_ADDR_LEN);

                        sr_send_packet(sr, currPkt->buf, currPkt->len, arpReq->ip, sr_interface);
                        currPkt = currPkt->next;
                    }
                    sr_arpreq_destroy(&sr->cache, arpReq);
                }
                break;struct sr_if* sr_interface;
            default:
                printf("Invalid Ethernet Type: %d\n", frame);
            }
        }
    }

}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
      /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d\n",len);

    /* fill in code here */
    unsigned int minLen = sizeof(sr_ethernet_hdr_t);
    if (minLen > len){
        fprintf(strderr, "Invalid ethernet frame length\n");
        return;
    }

    uint16_t frame = ethertype(packet);

    switch(frame){
        case ethertype_arp:
            sr_arp_handler(sr, packet, len, interface, minLen);
            break;
        case ethertype_ip:
            fprintf("Do something IP..\n");
            break;
        default:
            fprintf(stderr, "Unrecognized Ethernet Type\n");
            break;
    }

    /*if(frame == ethertype_arp){
    fprintf("Do something ARP..\n");
    }
    else if (frame == ethertype_ip){
    fprintf("Do something IP..\n");
    }
    else{
    fprintf(stderr, "Unrecognized Ethernet Type\n");
    }*/

}/* end sr_ForwardPacket */


