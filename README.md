# simple-router

### Overview

This router routes Ethernet packets between a host and clients with a static routing table by performing the following actions:

- Receives raw Ethernet frame

- If frame is an ARP packet

  - If it's an ARP request, construct an ARP reply and send it back
  - If it's an ARP reply, queue it for caching and send outstanding packets

- If frame is an IP packet

  - If it was sent to the router

    - If it's an ICMP echo request, send an echo reply
    - If it's a TCP/UCP packet, send ICMP port unreachable message
    - If it's neither, packet is discarded
    
  - If it's for someone else
    
    - Check checksum of the packet (discard if checksum is incorrect)
    - Send ICMP echo request if packet's TTL is 1, ICMP time exceeded message if TTL is less than 1, decrement TTL otherwise
    - Perform longest prefix match on the routing table (send ICMP net unreachable message if match is not found)
    - Check ARP cache for an entry
    - If ARP cache hit found
    - send packet to next hop interface
    - If no ARP cache entry found, send ARP request (if ARP request has already been sent 5 times, send ICMP host unreachable message)

### Design Considerations

