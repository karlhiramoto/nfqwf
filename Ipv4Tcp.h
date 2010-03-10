#ifndef IPV4_H
#define IPV4_H 1

#include <stdint.h>
#include <linux/in.h>

/**
* @defgroup Ipv4Tcp  TCP/IP version 4 defintions
* @{
*/

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
	uint16_t checksum;
	uint32_t seq_num;
	uint32_t ack_num;
	uint16_t packet_length; /// Length of IP packet
	uint16_t payload_length; /// Length of TCP payload
	void *data; /// pointer to raw IP packet data
	void *payload; /// pointer within data to TCP payload
};

/** @}  */

#endif

