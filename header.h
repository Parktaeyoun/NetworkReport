#pragma once
#include "pcap.h"
#include<arpa/inet.h>

#define ETHER_ADDR_LEN 6

typedef struct ether_header
{
    u_char dst_host[ETHER_ADDR_LEN];
    u_char src_host[ETHER_ADDR_LEN];
    u_short frame_type;
}ether_header;

typedef struct ip_header
{
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    u_char saddr[4]; // Source address
    u_char daddr[4]; // Destination address
    u_int op_pad; // Option + Padding
}ip_header;

typedef struct tcp_header
{
    u_short sport; // Source port
    u_short dport; // Destination port
    u_int seqnum; // Sequence Number
    u_int acknum; // Acknowledgement number
    u_char hlen; // Header length
    u_char flags; // packet flags
    u_short win; // Window size
    u_short crc; // Header Checksum
    u_short urgptr; // Urgent pointer...still don't know what this is...
}tcp_header;

