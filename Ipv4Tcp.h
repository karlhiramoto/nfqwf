#ifndef IPV4_H
#define IPV4_H 1

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/netlink.h>
#include <ubiqx/ubi_dLinkList.h>

/**
* @defgroup Ipv4Tcp  TCP/IP version 4 defintions
* @{
*/

#define HTTP_TCP_PORT 80
#define TCP_FLAG_SET(p,loc,flag) ((((int) *((int*) &p->ip_data[loc])) & flag) & __cpu_to_be32(0x00FF0000))

//byte offset int TCP header
#define TCP_FLAG_OFFSET 12

#define TCP_SEQ_HI_WRAPZONE 0xFFFFFFFF - 1500

struct Ipv4TcpTuple {
	in_addr_t src_ip;
	in_addr_t dst_ip;
	in_port_t src_port; // 16 bit port
	in_port_t dst_port;
};

/**
* TCP/IP version 4 packet.
* It can be a member of a linked list
*/
struct Ipv4TcpPkt {
	ubi_dlNode node;	/** ubiqx "internal" data */
	struct Ipv4TcpTuple tuple;
	uint32_t packet_id; /**< Linux Netlink Packet ID number */
	uint32_t seq_num; /**< TCP Sequence number */
	uint32_t ack_num; /**< TCP ACK number */
	uint16_t ip_checksum; /**< IP header checksum */
	uint16_t tcp_checksum; /**< TCP checksum */
	uint16_t ip_packet_length; /**< Length of IP packet */
	uint16_t tcp_payload_length; /**< Length of TCP payload */
	void *nl_buffer;  /**< pointer to raw netlink message buffer. */
	uint8_t *ip_data; /**< pointer to raw IP packet data */
	uint8_t *tcp_payload; /**< pointer within data to TCP payload */
	struct nfnl_queue_msg *nl_qmsg;
	uint8_t ip_hdr_len;
	uint8_t *modified_ip_data; /**< if not NULL the payload has been modified */
	unsigned int modified_ip_data_len;
};

unsigned short get_cksum16(const unsigned short *data, int len, int csum);

void Ipv4TcpPkt_resetTcpCksum(unsigned char *ip_pkt, unsigned int ip_pkt_size, unsigned int ip_hdr_len);

struct Ipv4TcpPkt *Ipv4TcpPkt_new(unsigned nl_buff_size);
void Ipv4TcpPkt_del(struct Ipv4TcpPkt **pkt);
struct Ipv4TcpPkt * Ipv4TcpPkt_clone(struct Ipv4TcpPkt *in_pkt);

int Ipv4TcpPkt_parseNlHdrMsg(struct Ipv4TcpPkt *pkt, struct nlmsghdr *nlh);
int Ipv4TcpPkt_parseIpPayload(struct Ipv4TcpPkt *pkt);
int Ipv4TcpPkt_printPkt(struct Ipv4TcpPkt *pkt, FILE *stream);

void Ipv4TcpPkt_setTcpFlag(struct Ipv4TcpPkt *pkt, int flag_val);
void Ipv4TcpPkt_clearTcpFlag(struct Ipv4TcpPkt *pkt, int flag_val);

void Ipv4TcpPkt_setNlVerictAccept(struct Ipv4TcpPkt *pkt);
void Ipv4TcpPkt_setNlVerictDrop(struct Ipv4TcpPkt *pkt);
void Ipv4TcpPkt_resetTcpCon(struct Ipv4TcpPkt *pkt);
void print_hex(const unsigned char* payload, int len);

/** @}  */

#endif

