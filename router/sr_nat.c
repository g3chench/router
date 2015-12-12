
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "sr_router.h"
#include "sr_utils.h"
#include <string.h>
#include <unistd.h>

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

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t caurtime = time(NULL);

    /* handle periodic tasks here */
    periodic_task(caurtime, nat);
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

void *periodic_task(time_t now, struct sr_nat *nat){
  struct sr_nat_mapping *current_mapping = nat->mappings;
  struct sr_nat_mapping *previous_mapping = NULL;
  struct sr_nat_mapping *delete_state;

  while (current_mapping) {
    struct sr_nat_mapping *next_mapping = current_mapping->next;
    if (nat_mapping_tcp == current_mapping->type) {
      /* Time out connections */
      struct sr_nat_connection *conn = current_mapping->conns;
      struct sr_nat_connection *prev_conn = NULL;

      while (conn) {
        if (((conn->state == outbound_syn_sent || 
          conn->state == syn_received) && difftime(now, conn->last_updated) > nat->tcp_trans_idle_timeout) || 
          (nat->tcp_est_idle_timeout < difftime(now,conn->last_updated) && conn->state == established)) {
          if (prev_conn) {
            prev_conn->next = conn->next;
          }
          else {
            current_mapping->conns = conn->next;
          }
        }
        else if (conn->state == unsol_syn_received && difftime(now, conn->last_updated) > 6.0) {
          sr_ip_hdr_t *ip_hdr = (struct sr_ip_hdr *)(conn->unsol_packet + sizeof(sr_ethernet_hdr_t));
          handle_ICMP(sr, PORT_UNREACHABLE, conn->unsol_packet, 0, ip_hdr->ip_dst);
          if (prev_conn) {
            prev_conn->next = conn->next;
          }
          else {
            current_mapping->conns = conn->next;
          }
        }
        prev_conn = conn;
        conn = conn->next;
      }
      previous_mapping = current_mapping;
      current_mapping = current_mapping->next;
    }    
    else if (nat_mapping_icmp == current_mapping->type) {
      if (nat->icmp_query_timeout >= difftime(now, current_mapping->last_updated)) {
        previous_mapping = current_mapping;
        current_mapping = next_mapping;
      }
      else {
        if (previous_mapping == NULL) {
          delete_state = current_mapping;
          nat->mappings = next_mapping;
          current_mapping = next_mapping;
        }
        else {
          delete_state = current_mapping;
          previous_mapping->next = next_mapping;
          current_mapping = next_mapping;
          free(delete_state);
        }
      }
    }

  }


}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

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
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
