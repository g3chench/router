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

sr_icmp_hdr_t gen_icmp_pkt (int type, int code=0, uint8_t cargo_len);
void send_icmp_unreachable(struct sr_instance *sr, struct sr_arpreq *req);

#endif
