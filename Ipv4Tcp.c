/*
Copyright (C) <2010-2011> Karl Hiramoto <karl@hiramoto.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

/*note this check for older kernels */
#ifndef aligned_be64
#define aligned_be64 u_int64_t __attribute__((aligned(8)))
#endif


#include <linux/netfilter/nfnetlink_queue.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/queue.h>
#include <netlink/netfilter/queue_msg.h>
#include <netlink/msg.h>
#include <netlink/object.h>

/**
* @defgroup Ipv4Tcp  TCP/IP version 4 defintions
* @{
*/

#include "Ipv4Tcp.h"
#include "nfq_wf_private.h"


struct Ipv4TcpPkt *Ipv4TcpPkt_new(unsigned nl_buff_size)
{
	struct Ipv4TcpPkt *new_pkt = calloc(1, sizeof(struct Ipv4TcpPkt));
	if (!new_pkt)
		return NULL;

	if (nl_buff_size) {
		new_pkt->nl_buffer = malloc(nl_buff_size);

		if (!new_pkt->nl_buffer) {
			free(new_pkt);
			return NULL;
		}
	}
	DBG(6, "new pkt %p size=%d\n", new_pkt, nl_buff_size);
	return new_pkt;
}

void Ipv4TcpPkt_del(struct Ipv4TcpPkt **in_pkt)
{
	struct Ipv4TcpPkt *pkt = *in_pkt;

	if(pkt->nl_qmsg)
		nfnl_queue_msg_put(pkt->nl_qmsg);

	if (pkt->nl_buffer)
		free(pkt->nl_buffer);

	DBG(6, "free pkt %p  qmsg=%p nl_buffer=%p\n", pkt, pkt->nl_qmsg, pkt->nl_buffer);
	free(pkt);
	*in_pkt = NULL;
}

// copy the packet, NOTE for now this is not an exact copy but a minimum size copy.
struct Ipv4TcpPkt * Ipv4TcpPkt_clone(struct Ipv4TcpPkt *in_pkt, bool copy_packet_data)
{
	struct Ipv4TcpPkt *new_pkt;

	new_pkt = Ipv4TcpPkt_new(copy_packet_data ? in_pkt->ip_packet_length : 0);

	DBG(6, "Clone of %d length\n", copy_packet_data ? in_pkt->ip_packet_length : 0);
	if (!new_pkt)
		return NULL;

	// copy info we need for new packet.
	new_pkt->tuple = in_pkt->tuple;
	new_pkt->seq_num = in_pkt->seq_num;
	new_pkt->ack_num = in_pkt->ack_num;
	new_pkt->tcp_flags = in_pkt->tcp_flags;
	new_pkt->ip_checksum = in_pkt->ip_checksum;
	new_pkt->tcp_checksum = in_pkt->tcp_checksum;
	new_pkt->ip_packet_length = in_pkt->ip_packet_length;
	new_pkt->tcp_payload_length = in_pkt->tcp_payload_length;

	// set IP packet pointer to buffer
	new_pkt->ip_data = new_pkt->nl_buffer;

	// set TCP payload pointer to correct offset in buffer
	new_pkt->tcp_payload = new_pkt->nl_buffer + (in_pkt->tcp_payload - in_pkt->ip_data);

	// copy IP packet data
	if (copy_packet_data)
		memcpy(new_pkt->ip_data, in_pkt->ip_data, in_pkt->ip_packet_length);

	return new_pkt;
}

static struct nla_policy queue_policy[NFQA_MAX+1] = {
	[NFQA_PACKET_HDR]		= {
		.minlen	= sizeof(struct nfqnl_msg_packet_hdr),
	},
	[NFQA_VERDICT_HDR]		= {
		.minlen	= sizeof(struct nfqnl_msg_verdict_hdr),
	},
	[NFQA_MARK]			= { .type = NLA_U32 },
	[NFQA_TIMESTAMP]		= {
		.minlen = sizeof(struct nfqnl_msg_packet_timestamp),
	},
	[NFQA_IFINDEX_INDEV]		= { .type = NLA_U32 },
	[NFQA_IFINDEX_OUTDEV]		= { .type = NLA_U32 },
	[NFQA_IFINDEX_PHYSINDEV]	= { .type = NLA_U32 },
	[NFQA_IFINDEX_PHYSOUTDEV]	= { .type = NLA_U32 },
	[NFQA_HWADDR]			= {
		.minlen	= sizeof(struct nfqnl_msg_packet_hw),
	},
};

#if 0
#if __BYTE_ORDER == __BIG_ENDIAN
static uint64_t ntohll(uint64_t x)
{
	return x;
}
#elif __BYTE_ORDER == __LITTLE_ENDIAN
static uint64_t ntohll(uint64_t x)
{
	return __bswap_64(x);
}
#endif
#endif

unsigned short get_cksum16(const unsigned short *data, int len, int csum)
{
	int nleft             = len;
	int sum               = csum;
	const unsigned short *w     = data;
	unsigned short answer = 0;

	/*
	* Our algorithm is simple, using a 32 bits accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while ( nleft > 1 ) {
//  		printf("sum=%hu=0x%hx word=%hu=0x%hx nleft=%d high16=%hu=0x%hx\n", sum, sum, *w, *w, nleft, (sum >> 16), (sum >> 16));
		sum   += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if ( nleft == 1 ) {
// 		*(unsigned char *) (&answer) = *(unsigned char *) w;
//  		printf("sum=%5hu=0x%04hx word=%5hu=0x%04hx nleft=%d\n", sum, sum, answer, answer, nleft);
// 		sum += answer;
		sum += htons(*(u_char *)w<<8);

	}

// 	printf("checksum sum1=%hu=0x%hx high16=%hu=0x%hx\n", sum, sum, (sum >> 16), (sum >> 16));

	/* add back carry outs from top 16 bits to low 16 bits */
	sum    =  (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
// 	printf("checksum sum2=%hu=0x%hx\n", sum, sum);
	sum    += (sum >> 16);  /* and carry */
// 	printf("checksum sum3=%hu=0x%hx\n", sum, sum);
	answer =  ~sum;         /* truncate to 16 bits */

//  	printf("checksum answer=%hu=0x%hx sum=%hu=0x%hx\n", answer, answer,  sum, sum);
	return answer;
}


void print_hex(const unsigned char* payload, int len)
{
	int line_pos;
	int offset = 0;
	int i;
	const int WIDTH = 16;

	while (len) {
		printf("Offset Ox%04X: ", offset);
		for (line_pos = 0; len && line_pos < WIDTH; line_pos++) {
			if (line_pos % 4 == 0)
				printf("  ");

			printf("%02X", payload[offset]);
			len--;
			offset++;
		}
		for (i = WIDTH - line_pos; i; i--) {
			printf("  ");
			if (i % 4 == 0)
				printf("  ");
		}

		offset -= line_pos;
		printf("   ");
		for ( ; line_pos ; line_pos--) {
			if (payload[offset] > 31 && payload[offset] < 127)
				printf("%c", payload[offset]);
			else
				printf(" ");

			offset++;
		}

		printf("\n");
	}
}

void Ipv4TcpPkt_resetTcpCksum(unsigned char *ip_pkt, unsigned int ip_pkt_size, unsigned int ip_hdr_len)
{
	uint16_t cksum;
	int sum;
	unsigned short *sptr;

	if (ip_hdr_len > ip_pkt_size) {
		ERROR_FATAL("Invalid packet and header size\n");
	}

	sptr = (unsigned short *) &ip_pkt[ip_hdr_len + 16];
	*sptr = 0; // set cksum to 0 to recalc

	sum = ((unsigned short) *((unsigned short*) &ip_pkt[12])) + // SRC
		((unsigned short) *((unsigned short*) &ip_pkt[14])) +
		((unsigned short) *((unsigned short*) &ip_pkt[16])) + // DST
		((unsigned short) *((unsigned short*) &ip_pkt[18])) +
		htons(IPPROTO_TCP) +  htons(ip_pkt_size - ip_hdr_len);

	cksum = get_cksum16((unsigned short *)&ip_pkt[ip_hdr_len],
					ip_pkt_size - ip_hdr_len, sum);

	*sptr = cksum;
}

void Ipv4TcpPkt_setTcpFlag(struct Ipv4TcpPkt *pkt, int flag_val)
{
	int *flag_data;
	if (!pkt->ip_data)
		return;
	flag_data = ((int*) &pkt->ip_data[pkt->ip_hdr_len+TCP_FLAG_OFFSET]);
	*flag_data |= flag_val;
}

void Ipv4TcpPkt_clearTcpFlag(struct Ipv4TcpPkt *pkt, int flag_val)

{
	int *flag_data;

	if (!pkt->ip_data)
		return;

	flag_data = ((int*) &pkt->ip_data[pkt->ip_hdr_len+TCP_FLAG_OFFSET]);
	*flag_data &= ~flag_val;
}


int Ipv4TcpPkt_printPkt(struct Ipv4TcpPkt *pkt, FILE *stream)
{
	char src_buf[20];
	char dst_buf[20];
	int tcp_flags_loc;

	inet_ntop(AF_INET, &pkt->ip_data[12], src_buf, sizeof(src_buf));
	inet_ntop(AF_INET, &pkt->ip_data[16], dst_buf, sizeof(dst_buf));
	fprintf(stream, "IP: src=%s dst=%s hdr_len=%hd=0x%hx ip_cksum=%hu=0x%hx ip_len=%hu=0x%hx\n",
			src_buf, dst_buf, pkt->ip_hdr_len, pkt->ip_hdr_len,
			pkt->ip_checksum, pkt->ip_checksum,
			pkt->ip_packet_length, pkt->ip_packet_length);

	fprintf(stream, "IP: DS=0x%02hhx ID=%u=0x%hx flags=0x%x Frag_Offset=0x%x TTL=%d proto=%d\n",
			pkt->ip_data[1],
			ntohs((uint16_t) *((uint16_t*) &pkt->ip_data[4])),
			ntohs((uint16_t) *((uint16_t*) &pkt->ip_data[4])),
 			(pkt->ip_data[6] >> 4),
			ntohs((uint16_t) *((uint16_t*) &pkt->ip_data[6])) & 0x0FFF,
		  pkt->ip_data[8], pkt->ip_data[9]);

	fprintf(stream, "TCP: sport=%hu dport=%hu cksum=0x%04X\n",
		pkt->tuple.src_port, pkt->tuple.dst_port, pkt->tcp_checksum);


	fprintf(stream, "Seq#=%u=0x%08x ACK#=%u=0x%08x TCP_CKSUM=%hu=0x%04hX TCP_LEN=%hd=0x%hx\n",
		pkt->seq_num, pkt->seq_num,
		pkt->ack_num, pkt->ack_num,
		pkt->tcp_checksum, pkt->tcp_checksum,
		pkt->tcp_payload_length, pkt->tcp_payload_length);

	tcp_flags_loc = pkt->ip_hdr_len+TCP_FLAG_OFFSET;
	fprintf(stream, "TCP: CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d\n",
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_CWR) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_ECE) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_URG) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_ACK) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_PSH) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_RST) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_SYN) ? 1:0,
		(((int) *((int*) &pkt->ip_data[tcp_flags_loc])) & TCP_FLAG_FIN) ? 1:0);

	return 0;
}


int Ipv4TcpPkt_parseIpPayload(struct Ipv4TcpPkt *pkt)
{
	unsigned char *payload = pkt->ip_data;
	unsigned char hdr_len;
	unsigned char protocol;
	uint16_t verify_cksum = 0;
	uint16_t total_len = 0;
	int tcp_data_offset;
	int sum;

	if (pkt->ip_packet_length < 32) {
		ERROR("PKT below min length len=%d\n", pkt->ip_packet_length);
		return -EINVAL;
	}
	// convert header length to number of bytes
	pkt->ip_hdr_len = hdr_len = (payload[0] & 0x0F) << 2;
	total_len = (payload[2] << 8) | payload[3];
	protocol = payload[9];

	if (protocol != IPPROTO_TCP) {
		ERROR("Protocol!=TCP %d\n", protocol);
		return -EINVAL;
	}

	verify_cksum = get_cksum16((unsigned short *)payload,
					pkt->ip_hdr_len, 0);

	pkt->ip_checksum =  ((unsigned short) *((unsigned short*) &payload[10]));

	if (verify_cksum) {
		DBG(1, "IP Header checksum ERROR ip_checksum= %hu = 0x%04hx  verify= %u =0x%04hx\n",
			pkt->ip_checksum, pkt->ip_checksum, verify_cksum, verify_cksum);
	} else {
		DBG(4, "IP header checksum OK\n");
	}

	// No need to convert to host byte order. inet_ntop() will do it for us,
	// and any compares in filter rules can be done in network byte order
	pkt->tuple.src_ip = ((int) *((int*) &payload[12]));
	pkt->tuple.dst_ip = ((int) *((int*) &payload[16]));

	// MAX header is 15 32bit words  15*4 = 60 bytes
	if (hdr_len > 60) {
		ERROR("Header too big=%d\n", hdr_len);
		return -EINVAL;
	}
	pkt->tuple.src_port = ntohs((short) *((short*) &payload[hdr_len]));
	pkt->tuple.dst_port = ntohs((short) *((short*) &payload[hdr_len+2]));

	pkt->seq_num = ntohl((int) *((int*) &payload[hdr_len+4]));
	pkt->ack_num = ntohl((int) *((int*) &payload[hdr_len+8]));
	tcp_data_offset = (payload[hdr_len+12] & 0xF0) >> 2; // byte offset
// 	pkt->doff_flags_window = (int) *((int*) &payload[hdr_len+12]);
	pkt->tcp_checksum = ((short) *((short*) &payload[hdr_len+16]));
	DBG(5, "TCP pkt_len=%d hdr_len=%d tcp_data_offset=%d=0x%x\n",
		pkt->ip_packet_length, hdr_len,
		tcp_data_offset, tcp_data_offset);
	pkt->tcp_payload_length = (pkt->ip_packet_length - hdr_len) - tcp_data_offset;
	pkt->tcp_payload = &payload[hdr_len+tcp_data_offset];

// 	DBG(5, "h[0]=0x%04hx h[1]=0x%04hx h[2]=0x%04hx h[3]=0x%04hx h[4]=0x%04hx h[5]=0x%04hx\n",
// 		((short) *((short*) &payload[12])), // SRC
// 		((short) *((short*) &payload[14])),
// 		((short) *((short*) &payload[16])), // DST
// 		((short) *((short*) &payload[18])),
// 		htons(IPPROTO_TCP),  htons(pkt->ip_packet_length - hdr_len));

	pkt->tcp_flags = ((int) *((int*) &payload[pkt->ip_hdr_len + TCP_FLAG_OFFSET])) & __cpu_to_be32(0x00FF0000);

	sum = ((unsigned short) *((unsigned short*) &payload[12])) + // SRC
			((unsigned short) *((unsigned short*) &payload[14])) +
			((unsigned short) *((unsigned short*) &payload[16])) + // DST
			((unsigned short) *((unsigned short*) &payload[18])) +
			htons(IPPROTO_TCP) +  htons(pkt->ip_packet_length - hdr_len);

	verify_cksum = get_cksum16((unsigned short *)&payload[hdr_len],
			pkt->ip_packet_length - hdr_len, sum);

	if (DEBUG_LEVEL > 5) {
		Ipv4TcpPkt_printPkt(pkt, stdout);
		print_hex(payload, pkt->ip_packet_length);
	}

	/* because we include the received checksum in the calculation,
	the verification sum should be 0 */
	if (verify_cksum) {
		ERROR("TCP Checksum error sum=0x%hx tcp_checksum=%d=0x%04hx\n", verify_cksum,
			  pkt->tcp_checksum, pkt->tcp_checksum);
		return -EINVAL;
	}
	return 0;
}

int Ipv4TcpPkt_parseNlHdrMsg(struct Ipv4TcpPkt *pkt, struct nlmsghdr *nlh)
{
	struct nlattr *tb[NFQA_MAX+1];
	struct nlattr *attr;
	int err;

	pkt->nl_qmsg = nfnl_queue_msg_alloc();

	if (!pkt->nl_qmsg)
		return -ENOMEM;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, NFQA_MAX,
			queue_policy);

	if (err < 0)
		goto errout;

	nfnl_queue_msg_set_group(pkt->nl_qmsg, nfnlmsg_res_id(nlh));
	nfnl_queue_msg_set_family(pkt->nl_qmsg, nfnlmsg_family(nlh));

	attr = tb[NFQA_PACKET_HDR];
	if (attr) {
		struct nfqnl_msg_packet_hdr *hdr = nla_data(attr);

		pkt->packet_id = ntohl(hdr->packet_id);
		DBG(3, "packet_id=%d\n", pkt->packet_id);

		nfnl_queue_msg_set_packetid(pkt->nl_qmsg, ntohl(hdr->packet_id));
		if (hdr->hw_protocol)
			nfnl_queue_msg_set_hwproto(pkt->nl_qmsg, hdr->hw_protocol);
		nfnl_queue_msg_set_hook(pkt->nl_qmsg, hdr->hook);
	}

	attr = tb[NFQA_MARK];
	if (attr)
		nfnl_queue_msg_set_mark(pkt->nl_qmsg, ntohl(nla_get_u32(attr)));

	#if 0
	/* for now we are not using time, and here is a timeval header issue */
	attr = tb[NFQA_TIMESTAMP];
	if (attr) {
		struct nfqnl_msg_packet_timestamp *timestamp = nla_data(attr);
		struct timeval tv;

		tv.tv_sec = ntohll(timestamp->sec);
		tv.tv_usec = ntohll(timestamp->usec);
		DBG(5, "Pkt time = %u.%06u", (unsigned)tv.tv_sec,(unsigned) tv.tv_usec);
		nfnl_queue_msg_set_timestamp(pkt->nl_qmsg, &tv);
	}
	#endif

	attr = tb[NFQA_IFINDEX_INDEV];
	if (attr)
		nfnl_queue_msg_set_indev(pkt->nl_qmsg, ntohl(nla_get_u32(attr)));

	attr = tb[NFQA_IFINDEX_OUTDEV];
	if (attr)
		nfnl_queue_msg_set_outdev(pkt->nl_qmsg, ntohl(nla_get_u32(attr)));

	attr = tb[NFQA_IFINDEX_PHYSINDEV];
	if (attr)
		nfnl_queue_msg_set_physindev(pkt->nl_qmsg, ntohl(nla_get_u32(attr)));

	attr = tb[NFQA_IFINDEX_PHYSOUTDEV];
	if (attr)
		nfnl_queue_msg_set_physoutdev(pkt->nl_qmsg, ntohl(nla_get_u32(attr)));

	attr = tb[NFQA_HWADDR];
	if (attr) {
		struct nfqnl_msg_packet_hw *hw = nla_data(attr);

		nfnl_queue_msg_set_hwaddr(pkt->nl_qmsg, hw->hw_addr,
				ntohs(hw->hw_addrlen));
	}

	attr = tb[NFQA_PAYLOAD];
	if (attr) {
		DBG(3, "Set payload len=%d\n", nla_len(attr));
		pkt->ip_packet_length = nla_len(attr);
		pkt->ip_data = nla_data(attr);
		// 		err = nfnl_queue_msg_set_payload(msg, nla_data(attr),
		// 						 nla_len(attr));

		// TODO parse IP packet
		Ipv4TcpPkt_parseIpPayload(pkt);
		if (err < 0)
			goto errout;
	}

	return 0;
	errout:

	return err;
}

#if 0
void Ipv4TcpPkt_setNlVerictAccept(struct Ipv4TcpPkt *pkt)
{
	nfnl_queue_msg_set_verdict(pkt->nl_qmsg, NF_ACCEPT);
}
#endif

void Ipv4TcpPkt_setNlVerictDrop(struct Ipv4TcpPkt *pkt) {
	nfnl_queue_msg_set_verdict(pkt->nl_qmsg, NF_DROP);
}


void Ipv4TcpPkt_resetTcpCon(struct Ipv4TcpPkt *pkt) {
	Ipv4TcpPkt_setTcpFlag(pkt, (TCP_FLAG_FIN | TCP_FLAG_RST)); // set FIN RST
	Ipv4TcpPkt_resetTcpCksum(pkt->ip_data, pkt->ip_packet_length, pkt->ip_hdr_len);
	pkt->modified_ip_data = pkt->ip_data; // mark modified
	pkt->modified_ip_data_len = pkt->ip_packet_length;
}

void Ipv4TcpPkt_setMark(struct Ipv4TcpPkt *pkt, uint32_t mark, uint32_t mask) {
	uint32_t old_mark;

	if (mask == -1) {
		nfnl_queue_msg_set_mark(pkt->nl_qmsg, mark);
	} else {
		old_mark = nfnl_queue_msg_get_mark(pkt->nl_qmsg);
		old_mark &= ~mask; // clear bits part of mask
		old_mark |= mark & mask;
		nfnl_queue_msg_set_mark(pkt->nl_qmsg, old_mark);
	}

}


/** @}  */

