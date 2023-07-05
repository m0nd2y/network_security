#ifndef _PCAP_TEST_H
# define _PCAP_TEST_H

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

int is_ip(const u_char* packet);
int is_tcp(const u_char* packet);
void print_eth(const u_char* packet);
void print_ip(const u_char* packet);
void print_tcp(const u_char* packet);
void print_data(const u_char* packet);

long unsigned int packet_length;

struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
	u_int16_t ether_type;
};

struct ip4_hdr
{
	uint8_t Version:4;
	uint8_t IHL:4;
	uint8_t TOS;
	uint16_t Total_length;
	uint16_t Identification;
	uint8_t Flags:4;
	uint8_t Fragment_offset_1:4;
	uint8_t Fragment_offset_2;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t Header_checksum;
	uint8_t  IP_src_mac[4];
	uint8_t  IP_dst_mac[4];
};

struct tcp_hdr
{
	uint16_t Source_port;
	uint16_t Destination_port;
	uint16_t Sequence_number[2];
	uint16_t Acknowledgement_number[2];
	uint8_t data_offset:4;
	uint8_t reserved:4;
	uint8_t flags;
	uint16_t Window_size;
	uint16_t Checksum;
	uint16_t Urgent_pointer;
};

struct Data
{
	uint8_t data[10];
};

#endif
