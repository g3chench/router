#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*
* Return a newly constructed ICMP packet struct given the type, code 
  and length of data the packet holds and the pointer to that data 
  as well.

*/
sr_icmp_hdr_t gen_icmp_pkt (int type, int code=0, uint8_t cargo_len) {
	sr_icmp_hdr_t *icmp_pkt = malloc(sizeof(icmp_hdr_t));
	
	switch (type) {
		case 0:
			/* echo reply*/
			icmp_pkt->icmp_type = 0;
		    icmp_pkt->icmp_code = 0;
		    
		case 3:
			/* unreachable interface */
			icmp_pkt->icmp_type = 3;

			switch (code) {

				/* destination unreachable*/
				case 0:
					icmp_pkt->icmp_code = 0;

				/* host unreachable*/
				case 1:
					icmp_pkt->icmp_code = 1;

				/* port unreachable*/
				case 3:
					icmp_pkt->icmp_code = 3;

				/* invalid icmp type to use*/
				default:
					fprintf("unsupported ICMP code specified.\n");
					return ;
			}

		case 11:
			/* time exceeded */
			icmp_pkt->icmp_type = 11;
		    icmp_pkt->icmp_code = 0;

		default:
			/* unsupported icmp type*/
			fprintf("unsupported ICMP type\n");
			return ;
	}


	icmp_pkt->data[ICMP_DATA_SIZE];
	icmp_pkt->icmp_sum = cksum(icmp_pkt + cargo_len);


	return icmp_pkt;
}

