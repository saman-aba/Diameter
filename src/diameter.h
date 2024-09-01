#ifndef __DIAMETER_H__
#define __DIAMETER_H__

/* Table 1 - Data Formats

	OctetString 	- Variable length and must be padded to aligned in 32 bits
	Integer32	12(16)
	Integer64	16(20)
	Unsigned32	12(16)
	Unsigned64	16(20)
	Float32		12(16)
	Float64		16(20)
	Grouped		8(12) + the total length of included avps
*/

/* Table 3 - Result-Code AVP answers
	1xxx - Informational
	2xxx - Success
	3xxx - Protocol errors
	4xxx - Transient errors
	5xxx - Permanent failure
*/

#include <string.h>
#include "avp.h"
#include "diameter_dict.h"

#define DIAMETER_MULTI_ROUND_AUTH               1001

#define DIAMETER_SUCCESS                        2001
#define DIAMETER_LIMITED_SUCCESS                2002

#define DIAMETER_COMMAND_UNSUPPORTED            3001
#define DIAMETER_UNABLE_TO_DELIVER              3002
#define DIAMETER_REALM_NOT_SERVED               3003
#define DIAMETER_TOO_BUSY                       3004
#define DIAMETER_LOOP_DETECTED                  3005
#define DIAMETER_REDIRECT_INDICATION            3006
#define DIAMETER_APPLICATION_UNSUPPORTED        3007
#define DIAMETER_INVALID_HDR_BITS               3008
#define DIAMETER_INVALID_AVP_BITS               3009
#define DIAMETER_UNKNOWN_PEER                   3010

#define DIAMETER_AUTHENTICATION_REJECTED        4001
#define DIAMETER_OUT_OF_SPACE                   4002
#define ELECTION_LOST                           4003

#define DIAMETER_AVP_UNSUPPORTED                5001
#define DIAMETER_AVP_UNKNOWN_SESSION_ID         5002
#define DIAMETER_AUTHORIZATION_REJECTED         5003
#define DIAMETER_INVALID_AVP_VALUE              5004
#define DIAMETER_MISSING_AVP                    5005
#define DIAMETER_RESOURCE_EXCEEDED              5006
#define DIAMETER_CONTRADICTING_AVPS             5007
#define DIAMETER_AVP_NOT_ALLOWED                5008
#define DIAMETER_AVP_OCCURS_TOO_MANY_TIMES      5009
#define DIAMETER_NO_COMMON_APPLICATION          5010
#define DIAMETER_UNSUPPORTED_VERSION            5011
#define DIAMETER_UNABLE_TO_COMPLY               5012
#define DIAMETER_INVALID_BIT_IN_HEADER          5013
#define DIAMETER_INVALID_AVP_LENGTH             5014
#define DIAMETER_INVALID_MESSAGE_LENGTH         5015
#define DIAMETER_INVALID_AVP_BIT_COMBO          5016
#define DIAMETER_NO_COMMON_SECURITY             5017

typedef enum {
	OctetString,
	Integer32,
	Integer64,
	Unsigned32,
	Unsigned64,
	Float32,
	Float64,
	Grouped
} avp_type;


//unsigned int 	r:1; /*	(1)Request/
//			(0)Answer */
//unsigned int 	p:1; /*	(1)Proxied,Relayed,Redirected/
//			(0)*/
//unsigned int	e:1; /* (1)Request caused error/
//		(0)*/
//unsigned int 	t:1;
//unsigned int 	reserved:4;

struct diameter_hdr{
#define DIAMETER_HEADER_LEN
	union{
		unsigned int 				raw1;
		struct{
			unsigned int 			version:8;
			unsigned int 			length:24;
		};
	};
	union{
		unsigned int 				raw2;
		struct{
			unsigned int 			flags:8;
			unsigned int			command_code:24;
		};
	};
	unsigned int 					application_id;
	unsigned int 					hop_by_hop_id;
	unsigned int 					end_to_end_id;
};

struct diameter_avp_hdr{
	unsigned int 					code;
	union{
		unsigned int 				raw2;	
		struct{
			unsigned int 			flags:8;
			unsigned int 			length:24;
		};
	};
};

#define AVP_HEADER_SIZE                         8
struct diameter_avp{
	unsigned short					id;
	avp_type					type;
	unsigned short					pad;
	unsigned int					vendor_id;
	struct diameter_avp_hdr				header;
	void 						*data;
};

struct diameter_pkt{
	struct diameter_hdr 				header;
	unsigned short					lsize;
#define AVP_LIST_SIZE	64
	struct diameter_avp				*list[AVP_LIST_SIZE];
};

#define AVP_HEADER(avp_ptr) 	(avp_ptr->header)
#define AVP_DATA(avp_ptr) 	avp_ptr->data + AVP_HEADER_SIZE

//#define FOREACH_DIAMETER_AVP()

static inline char
diameter_vendor_id_present_avp(const struct diameter_avp *avp)
{
	return (AVP_HEADER(avp).flags & 0x80);
}

static inline char
diameter_set_vencor_id_present_avp(struct diameter_avp *avp)
{
	AVP_HEADER(avp).flags |= 0x80;
}

static inline char
diameter_mandatory_avp(const struct diameter_avp *avp)
{
	return (AVP_HEADER(avp).flags & 0x40);
}

static inline void
diameter_set_mandatory_avp(struct diameter_avp *avp)
{
	AVP_HEADER(avp).flags |= 0x40;
}

struct diameter_avp*
diameter_new_avp(unsigned int code, unsigned char flags);

struct diameter_pkt *
diameter_new_packet(unsigned char flags);

void
diameter_insert_avp(struct diameter_pkt *pkt, 
		struct diameter_avp *in);

void
diameter_insert_avp_after(struct diameter_pkt *pkt, 
		struct diameter_avp *node, 
		struct diameter_avp *newavp);

void
diameter_insert_avp_before(struct diameter_pkt *pkt, 
		struct diameter_avp *avp);

void
diameter_swap_avp(struct diameter_pkt *pkt, 
		const unsigned int first, 
		const unsigned int second);

void
diameter_remove_avp(struct diameter_pkt *pkt, 
		unsigned short id);

int
diameter_serialize_packet(const struct diameter_pkt *pkt, char *buf);

void
diameter_deserialize_packet(const char *buf, int buf_size, struct diameter_pkt *pkt);

void
diameter_print_packet(const struct diameter_pkt *pkt);



#endif
