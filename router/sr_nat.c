#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_ip.h"
#include "sr_icmp.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */
  nat->mappings = NULL;
  /* Initialize any variables here */

  memset(nat->used_icmp_ids, 0, sizeof(nat->used_icmp_ids));
  memset(nat->used_tcp_ports, 0, sizeof(nat->used_tcp_ports));

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */

  struct sr_instance *sr = (struct sr_instance *)sr_ptr;
  struct sr_nat *nat = sr->nat;
  
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t now = time(NULL);

    /* handle periodic tasks here */

    struct sr_nat_mapping *prev_mapping = NULL;
    struct sr_nat_mapping *curr_mapping = nat->mappings;
    struct sr_nat_mapping *delete;
    
    while (curr_mapping != NULL) {
      if (curr_mapping->type == nat_mapping_icmp) {
        if (difftime(now, curr_mapping->last_updated) > nat->icmp_query_timeout) {
          
          if (prev_mapping) {
            prev_mapping->next = curr_mapping->next;
            delete = curr_mapping;
            curr_mapping = curr_mapping->next;
            free(delete);
          } else {
            nat->mappings = curr_mapping->next;
            delete = curr_mapping;
            curr_mapping = curr_mapping->next;
            free(delete);
          }

        } else {
          prev_mapping = curr_mapping;
          curr_mapping = curr_mapping->next;
        }

      } else if (curr_mapping->type == nat_mapping_tcp) {

        /* Connection timeout */
        struct sr_nat_connection *prev_conn = NULL;
        struct sr_nat_connection *conn = curr_mapping->conns;

        while (conn) {

          if ((conn->state == established && difftime(now, conn->last_updated) > nat->tcp_est_idle_timeout) ||
              ((conn->state == outbound_syn_sent || conn->state == syn_received) && difftime(now, conn->last_updated) > nat->tcp_trans_idle_timeout)) {

            if (prev_conn) {
              prev_conn->next = conn->next;
            } else {
              curr_mapping->conns = conn->next;
            }

          } else if (conn->state == unsolicited_syn_received && difftime(now, conn->last_updated) > 6.0) {

            sr_ip_hdr_t *ip_hdr = (struct sr_ip_hdr *)(conn->unsolicited_packet + sizeof(sr_ethernet_hdr_t));
            handle_ICMP(sr, PORT_UNREACHABLE, conn->unsolicited_packet, 0, ip_hdr->ip_dst);
            
            if (prev_conn) {
              prev_conn->next = conn->next;
            } else {
              curr_mapping->conns = conn->next;
            }
          }

          prev_conn = conn;
          conn = conn->next;
        }

        prev_mapping = curr_mapping;
        curr_mapping = curr_mapping->next;
      }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping) {

    if (mapping->aux_ext == aux_ext && mapping->type == type) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      mapping->last_updated = time(NULL);
      break;
    }

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping) {

    if (mapping->ip_int == ip_int && mapping->aux_int == aux_int 
        && mapping->type == type) {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      mapping->last_updated = time(NULL);
      break;
    }

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *mapping_copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;

  if (get_port_number(nat, type) == -1) {
    fprintf(stderr, "ERROR: invalid port number\n");
  }
  mapping->aux_ext = htons(get_port_number(nat, type));

  mapping->conns = NULL;
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  memcpy(mapping_copy, mapping, sizeof(struct sr_nat_mapping));

  mapping->last_updated = time(NULL);

  pthread_mutex_unlock(&(nat->lock));
  return mapping_copy;
}

/* Return an ICMP ID for an ICMP mapping or an unused port number for a TCP mapping*/
int get_port_number(struct sr_nat *nat, sr_nat_mapping_type type) {

  uint16_t i = -1;

  if (type == nat_mapping_icmp) {

    for (i = 0; i < 65535; i++) {
      if (!nat->used_icmp_ids[i]) {
        nat->used_icmp_ids[i] = 1;
        return i;
      }
    }

  } else if (type == nat_mapping_tcp) {

    for (i = 0; i < 64511; i++) {
      if (!nat->used_tcp_ports[i]) {
        nat->used_tcp_ports[i] = 1;
        return i + 1024;
      }
    }
  }

  return i;
}

void handle_nat(struct sr_instance* sr,
                uint8_t * packet,
                unsigned int len,
                char* interface) {

  struct sr_nat *nat = sr->nat;
  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  int ip_hl = ip_hdr->ip_hl * 4;
  uint8_t ip_protocol = ip_hdr->ip_p;

  if (ip_protocol == ip_protocol_icmp) {

    sr_icmp_t0_hdr_t *icmp_hdr = (sr_icmp_t0_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Internal interface */
    if (!strncmp(interface, INTERNAL_INTERFACE, sr_IFACE_NAMELEN)) {

      struct sr_nat_mapping *map = sr_nat_lookup_internal(nat, ip_hdr->ip_src, icmp_hdr->id, nat_mapping_icmp);
      
      /* No mapping found */
      if (!map) {
        map = sr_nat_insert_mapping(nat, ip_hdr->ip_src, icmp_hdr->id, nat_mapping_icmp);
      }

      /* Update IP headers */
      ip_hdr->ip_src = sr_get_interface(sr, EXTERNAL_INTERFACE)->ip;
      icmp_hdr->id = map->aux_ext;
      icmp_hdr->icmp_sum = 0;
      icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

      forward_IP_packet(sr, packet, len);
    }

    /* External interface */
    else if (!strncmp(interface, EXTERNAL_INTERFACE, sr_IFACE_NAMELEN)) {

      struct sr_nat_mapping *map = sr_nat_lookup_external(nat, icmp_hdr->id, nat_mapping_icmp);

      /* Inbound */
      if (map) {

        ip_hdr->ip_dst = map->ip_int;
        icmp_hdr->id = map->aux_int;
        icmp_hdr->icmp_sum = 0;
        icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

        forward_IP_packet(sr, packet, len);

      } else {

        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* ICMP echo request */
        if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {

          uint16_t packet_cksum_icmp = icmp_hdr->icmp_sum;
          icmp_hdr->icmp_sum = 0;
          uint16_t calculated_checksum_icmp = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
          
          if (packet_cksum_icmp == calculated_checksum_icmp) {
            icmp_hdr->icmp_sum = packet_cksum_icmp;
            handle_ICMP(sr, ECHO_REPLY, packet, len, 0);
          } else {
            fprintf(stderr, "ERROR: checksum mismatch\n");
          }
        }
      }

    } else {
      fprintf(stderr, "ERROR: packet is from unrecognized interface.\n");
    }

  } else if (ip_protocol == ip_protocol_tcp) {
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    if (!strncmp(interface, INTERNAL_INTERFACE, sr_IFACE_NAMELEN)) {

      struct sr_nat_mapping *map = sr_nat_lookup_internal(nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);
      
      /* No mapping found */
      if (!map) {
        map = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);
      }
      
      update_tcp_conn(nat, map, packet, len, 2);

      /* Update IP headers */
      ip_hdr->ip_src = sr_get_interface(sr, EXTERNAL_INTERFACE)->ip;
      tcp_hdr->src_port = map->aux_ext;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
      tcp_hdr->tcp_sum = 0;
      
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      unsigned int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
      unsigned int total_len = sizeof(sr_tcp_temp_hdr_t) + tcp_len;
      uint8_t *temp_hdr_buf = malloc(total_len);
      sr_tcp_temp_hdr_t *temp_hdr = (sr_tcp_temp_hdr_t *)temp_hdr_buf;

      temp_hdr->ip_src = ip_hdr->ip_src;
      temp_hdr->ip_dst = ip_hdr->ip_dst;
      temp_hdr->blank = 0;
      temp_hdr->ip_p = ip_hdr->ip_p;
      temp_hdr->length = htons(tcp_len);
      memcpy(temp_hdr_buf + sizeof(sr_tcp_temp_hdr_t), tcp_hdr, tcp_len);

      tcp_hdr->tcp_sum = cksum(temp_hdr_buf, total_len);

      free(temp_hdr_buf);
      free(map);
      forward_IP_packet(sr, packet, len);

    } else if (!strncmp(interface, EXTERNAL_INTERFACE, sr_IFACE_NAMELEN)) {
      struct sr_nat_mapping *map = sr_nat_lookup_external(nat, tcp_hdr->dst_port, nat_mapping_tcp);
      
      if (map) {
        if (!update_tcp_conn(nat, map, packet, len, 1)) {
          ip_hdr->ip_dst = map->ip_int;
          tcp_hdr->dst_port = map->aux_int;
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
          tcp_hdr->tcp_sum = 0;
          
          unsigned int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
          unsigned int total_len = sizeof(sr_tcp_temp_hdr_t) + tcp_len;
          uint8_t *temp_hdr_buf = malloc(total_len);
          sr_tcp_temp_hdr_t *temp_hdr = (sr_tcp_temp_hdr_t *)temp_hdr_buf;

          temp_hdr->ip_src = ip_hdr->ip_src;
          temp_hdr->ip_dst = ip_hdr->ip_dst;
          temp_hdr->blank = 0;
          temp_hdr->ip_p = ip_hdr->ip_p;
          temp_hdr->length = htons(tcp_len);
          memcpy(temp_hdr_buf + sizeof(sr_tcp_temp_hdr_t), tcp_hdr, tcp_len);

          tcp_hdr->tcp_sum = cksum(temp_hdr_buf, total_len);

          free(temp_hdr_buf);
          free(map);
          forward_IP_packet(sr, packet, len);
        }

      } else if (tcp_hdr->ctrl_flags & SYN_FLAG) { /* Unsolicited inbound syn (most likely for simultaneous open) */
        map = sr_nat_insert_mapping(nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);
        update_tcp_conn(nat, map, packet, len, 1);
      }

    } else {
      fprintf(stderr, "ERROR: packet from unrecognized interface.\n");
    }

  } else {
    fprintf(stderr, "ERROR: unsupported IP protocol type");
  }
}

/* Update TCP connections for mapping corresponding to mapping_copy */
int update_tcp_conn(struct sr_nat *nat, 
                    struct sr_nat_mapping *mapping_copy, 
                    uint8_t *packet,
                    unsigned int len,
                    int direction) {

  pthread_mutex_lock(&(nat->lock));

  int output = 0;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint8_t flags = tcp_hdr->ctrl_flags;
  uint32_t ip;
  uint16_t port;

  if (direction == 2) {
    ip = ip_hdr->ip_dst;
    port = tcp_hdr->dst_port;
  } else {
    ip = ip_hdr->ip_src;
    port = tcp_hdr->src_port;
  }

  /* Find actual mapping */
  struct sr_nat_mapping *mapping = nat->mappings;
  while (mapping &&
         mapping->ip_int != mapping_copy->ip_int &&
         mapping->ip_ext != mapping_copy->ip_ext &&
         mapping->aux_int != mapping_copy->aux_int &&
         mapping->aux_ext != mapping_copy->aux_ext) {
    mapping = mapping->next;
  }

  struct sr_nat_connection *prev = NULL;
  struct sr_nat_connection *conn = mapping->conns;

  while (conn && conn->ip != ip && conn->port != port) {
    prev = conn;
    conn = conn->next;
  }

  if (conn) {
    if (update_conn_state(conn, flags, direction)) {

      /* Connection closed*/
      if (prev) {
        prev->next = conn->next;
      } else {
        mapping->conns = conn->next;
      }
    }

  } else {

    if (flags & SYN_FLAG) {
      tcp_conn_state state;

      if (direction == 2) {
        state = outbound_syn_sent;
      } else {
        state = unsolicited_syn_received;
        output = 1;
      }

      /* Need to insert new connection */
      struct sr_nat_connection *new_connection = (struct sr_nat_connection *)(malloc(sizeof(struct sr_nat_connection)));
      new_connection->ip = ip;
      new_connection->port = port;
      new_connection->state = state;

      if (state == unsolicited_syn_received) {
        new_connection->unsolicited_packet = malloc(len);
        memcpy(new_connection->unsolicited_packet, packet, len);
      }

      new_connection->last_updated = time(NULL);
      new_connection->next = mapping->conns;
      mapping->conns = new_connection;
    }   
  }

  mapping->last_updated = time(NULL);

  pthread_mutex_unlock(&(nat->lock));
  return output;
}

/* Updates state member for a given connection 
    1 for inbound packets
    2 for outbound packets
*/
int update_conn_state(struct sr_nat_connection *connection,
                      uint8_t flags,
                      int direction) {

  int output = 0;

  if (connection->state == unsolicited_syn_received && direction == 2 && (flags & SYN_FLAG)) {
    connection->state = outbound_syn_sent;

  } else if (connection->state == outbound_syn_sent) {

    if (direction == 1) {
      if ((flags & SYN_FLAG) && (flags & ACK_FLAG)) {
        connection->state = established;
      } else if (flags & SYN_FLAG) {
        connection->state = syn_received;
      }
    }

  } else if (connection->state == syn_received && direction == 1 && (flags & ACK_FLAG)) {
    connection->state = established;
  } else if (connection->state == established && direction == 2 && (flags & FIN_FLAG)) {
    connection->state = fin_1;
  } else if (connection->state == fin_1 && direction == 1 && (flags & ACK_FLAG)) {
    connection->state = fin_2;
  } else if (connection->state == fin_2 && direction == 1 && (flags & FIN_FLAG)) {
    connection->state = fin_3;
  } else if (connection->state == fin_3 && direction == 2 && (flags & ACK_FLAG)) {
    connection->state = closed;
    output = 1;
  }

  connection->last_updated = time(NULL);
  return output;
}
