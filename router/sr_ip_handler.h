#ifndef SR_IP_HANDLER_H
#define SR_IP_HANDLER_H

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void ip_handler(struct sr_instance* sr, uint8_t *packet, unsigned int len, char *interface);

struct sr_if* get_output_interface(struct sr_instance* sr, uint32_t address;

#endif
