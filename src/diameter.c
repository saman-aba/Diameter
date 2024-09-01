
#include "diameter.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "val_str.h"
#include <arpa/inet.h>
static const val_str avp_display[] = {
	{DIAMETER_USER_NAME,		"User-Name"},
	{DIAMETER_HOST_IP_ADDRESS,	"Host-IP-Address"},
	{DIAMETER_AUTH_APPLICATION_ID,	"Auth-Application-Id"},
	{DIAMETER_ACCT_APPLICATION_ID,	"Acct-Application-Id"},
	{DIAMETER_VENDOR_SPECIFIC_APPLICATION_ID,	"Vendor-Specific-Application-Id"},
	{DIAMETER_SESSION_ID, 		"Session-Id"},
	{DIAMETER_ORIGIN_HOST, 		"Origin-Host"},
	{DIAMETER_SUPPORTED_VENDOR_ID,	"Supported-Vendor-Id"},
	{DIAMETER_VENDOR_ID,		"Vendor-Id"},
	{DIAMETER_FIRMWARE_REVISION,	"Firmware-Revision"},
	{DIAMETER_RESULT_CODE,		"Result-Code"},
	{DIAMETER_PRODUCT_NAME,		"Product-Name"},
	{DIAMETER_RESULT_CODE, 		"Result-Code"},
	{DIAMETER_ORIGIN_STATE_ID,	"Origin-State-Id"},
	{DIAMETER_AUTH_SESSION_STATE,	"Auth-Session-State"},
	{DIAMETER_PROXY_HOST,		"Proxy-Host"},
	{DIAMETER_ROUTE_RECORD,		"Route-Record"},
	{DIAMETER_DESTINATION_REALM,	"Destination-Realm"},
	{DIAMETER_PROXY_INFO,		"Proxy-Info"},
	{DIAMETER_DESTINATION_HOST,	"Destination-Host"},
	{DIAMETER_ORIGIN_REALM,		"Origin-Realm"},
	{DIAMETER_EXPERIMENTAL_RESULT,	"Experimental-Result"},
	{DIAMETER_INBAND_SECURITY_ID,	"Inband-Security-Id"},
	{DIAMETER_VISITED_PLMN_ID,	"Visited-PLMN-Id"},
	{DIAMETER_ULA_FLAGS,		"ULA-Flags"},
	{DIAMETER_SUBSCRIPTION_DATA,	"Subscription-Data"}
};
	
struct diameter_avp *diameter_new_avp(unsigned int code, 
		unsigned char flags)
{
	struct diameter_avp *avp = diameter_avp_dict_code_lookup(code);
	
	AVP_HEADER(avp).flags = flags;

//	if(flags & 0x80)
//	{
//		AVP_HEADER(avp).length += sizeof(unsigned int);
//	}
	return avp;
}

struct diameter_pkt *diameter_new_packet(unsigned char flags)
{	
	struct diameter_pkt *pkt = 
		calloc(1, sizeof(struct diameter_pkt));
	pkt->header.version = 1;
	pkt->header.length = 20;
	pkt->header.flags = flags;
	pkt->header.application_id = 16777251;
	return pkt;
}


void diameter_insert_avp(struct diameter_pkt *pkt, struct diameter_avp *obj)
{
	int index = 0;
	while(pkt->list[index])
		index++;
	if(index > AVP_LIST_SIZE - 1)
		return;
	pkt->list[index] = obj;	
	pkt->lsize++;
	
	pkt->header.length += AVP_HEADER(obj).length;
	pkt->header.length += obj->pad;
}

void diameter_insert_avp_after(struct diameter_pkt *pkt, 
		struct diameter_avp *node, struct diameter_avp *newavp)
{
	struct diameter_avp *tmp;
	unsigned index = pkt->lsize;
	while(pkt->list[index] != node)
	{
		pkt->list[index + 1] = pkt->list[index];
		index--;
	
		if(!index) 
			return;
	}
	pkt->list[index + 1] = newavp;
}

void diameter_insert_avp_before(struct diameter_pkt *pkt, struct diameter_avp *avp)
{

}

void
diameter_swap_avp(struct diameter_pkt *pkt, 
		const unsigned int first, const unsigned int second)
{
	struct diameter_avp *tmp = 0;
	if(pkt->list[first] && pkt->list[second]);
	{
		tmp = pkt->list[first];
		pkt->list[first] = pkt->list[second];
		pkt->list[second] = tmp;
	}
}

void
diameter_remove_avp(struct diameter_pkt *pkt, unsigned short index)
{
	int i = 0;
	if(pkt->list[index])
	{
		pkt->header.length -= (pkt->list[index]->header.length + pkt->list[index]->pad);
		free(pkt->list[index]->data);
		free(pkt->list[index]);
		i = index +1;
		
		while(pkt->list[i]){
			pkt->list[i - 1] = pkt->list[i];
			i++;
		}
		pkt->lsize--;
		pkt->list[pkt->lsize] = NULL;
	}
}

int
_serialize_diameter_avp(struct diameter_avp *avp, char *buf)
{
	int offt = 0;
	int data_sz;
	
	struct diameter_avp_hdr tmphdr = {0};
	
	tmphdr.code = htonl(avp->header.code);
	tmphdr.flags = avp->header.flags;

	tmphdr.length = ((avp->header.length & 0x0000ff) << 16) |
			(avp->header.length & 0x00ff00) 	|
			(avp->header.length & 0xff0000);
	
	memcpy(buf, &tmphdr, sizeof(struct diameter_avp_hdr));
	offt += sizeof(struct diameter_avp_hdr);
	
	data_sz = avp->header.length - sizeof(struct diameter_avp_hdr);

	if(avp->header.flags & 0x80){
		unsigned int vendor_hton = htonl(avp->vendor_id);	
		memcpy(buf + offt, &vendor_hton, sizeof(unsigned int));
		offt += sizeof(unsigned int);
		data_sz -= sizeof(unsigned int);

	}
	memcpy(buf + offt, avp->data, data_sz);
	offt += data_sz;
	
	if(avp->pad)
		memset(buf + offt, 0, avp->pad);
		
	offt += avp->pad;
	
	return offt;
}
	
int
diameter_serialize_packet(const struct diameter_pkt *pkt, char *buf)
{
	int 	i = 0,
		offt = 0, 
		avp_size = 0;
	struct diameter_hdr tmphdr = {0};
	tmphdr.version = pkt->header.version;
	
	tmphdr.length = 	((pkt->header.length & 0x0000ff) << 16) 	|
				((pkt->header.length & 0x00ff00))		|
				((pkt->header.length & 0xff0000));
	tmphdr.flags = pkt->header.flags;
	tmphdr.command_code = 	((pkt->header.command_code & 0x0000ff) << 16) 	|
				((pkt->header.command_code & 0x00ff00))		|
				((pkt->header.command_code & 0xff0000));
	
	tmphdr.application_id = htonl(pkt->header.application_id);
	tmphdr.hop_by_hop_id = htonl(pkt->header.hop_by_hop_id);
	tmphdr.end_to_end_id = htonl(pkt->header.end_to_end_id);
	
	memcpy(buf, &tmphdr, sizeof(struct diameter_hdr));
	offt += sizeof(struct diameter_hdr);
	
	for(; i < AVP_LIST_SIZE ; i++)
	{
		if(!(pkt->list[i]))
			break;
		avp_size = _serialize_diameter_avp(pkt->list[i], 
				buf + offt);
		offt += avp_size;	
	}
	return offt;
}

void
diameter_deserialize_packet(const char *buf, int buf_size, struct diameter_pkt *pkt)
{
	int offt = 0;
	
	struct diameter_hdr tmp_dimhdr;

	memcpy(&tmp_dimhdr,buf ,sizeof(struct diameter_hdr));

	pkt->header.version = tmp_dimhdr.version;
	pkt->header.length = ntohl(tmp_dimhdr.length);
	pkt->header.length = 	((tmp_dimhdr.length & 0x0000ff) << 16)	|
				((tmp_dimhdr.length & 0x00ff00) << 8)	|
				((tmp_dimhdr.length & 0xff0000));

	pkt->header.flags = tmp_dimhdr.flags;
	pkt->header.command_code = 	((tmp_dimhdr.command_code & 0x0000ff) << 16) 	|
					((tmp_dimhdr.command_code & 0x00ff00) << 8)	|
					((tmp_dimhdr.command_code & 0xff0000));

	pkt->header.application_id = ntohl(tmp_dimhdr.application_id);
	pkt->header.hop_by_hop_id = ntohl(tmp_dimhdr.hop_by_hop_id);
	pkt->header.end_to_end_id = ntohl(tmp_dimhdr.end_to_end_id);

	offt += sizeof(struct diameter_hdr);


	struct diameter_avp_hdr tmp_avphdr;
	int data_sz;

	while(offt < buf_size)
	{
		memset(&tmp_avphdr, 0, sizeof(struct diameter_avp_hdr));
		struct diameter_avp *avp = malloc(sizeof(struct diameter_avp));
		
		memcpy(&tmp_avphdr, buf + offt, sizeof(struct diameter_avp_hdr));
		offt += sizeof(struct diameter_avp_hdr);
		
		avp->header.code = ntohl(tmp_avphdr.code);
		avp->header.flags = tmp_avphdr.flags;
		avp->header.length = 	((tmp_avphdr.length & 0x0000ff) << 16)	|
					((tmp_avphdr.length & 0x00ff00) << 8)	|
					((tmp_avphdr.length & 0xff0000));
		
		data_sz = avp->header.length - sizeof(struct diameter_avp_hdr);
		avp->pad = (4 - data_sz%4)%4;
	
		avp->data = malloc(data_sz + avp->pad);
		memcpy(avp->data, buf + offt, data_sz);
		offt += data_sz;
		if(avp->pad)
		{
			memset(avp->data, 0, avp->pad);
			offt += avp->pad;
		};

		diameter_insert_avp(pkt,avp);
	}
}

void
diameter_print_packet(const struct diameter_pkt *pkt)
{
	unsigned i;
	assert(pkt);
	printf("\t------------------Diameter-------------------\n");
	printf("\tVersion:%10d\n", pkt->header.version);
	printf("\tLength:\t%10u\n", pkt->header.length);
	printf("\tFlags:\n");
	printf("\t	------AVPS-------	\n");
	
	struct diameter_avp *avp;
	for(i = 0; i < AVP_LIST_SIZE ;i++){
		
		avp = pkt->list[i];
		if(!avp) break;
		char *avp_name = string_from_value(avp->header.code, 
					avp_display, 
					"Unknown");
		printf("\t\tAVP %d \t(%s)\n", i, avp_name);
				
		printf("\t\tCode \t\t: %u\n", avp->header.code);
		printf("\t\tLength \t\t: %u\n", avp->header.length);
		printf("\t\t%s \t:",avp_name);
		switch(avp->type)
		{
			case OctetString:
				printf("\n\t\t\t%s\n", 
					(char *)avp->data);
				break;
			case Integer32:
				printf(" %d\n", *(int *)avp->data );
		}
		printf("\n");
	}
	printf("\n");
}


