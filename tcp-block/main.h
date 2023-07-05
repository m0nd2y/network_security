#ifndef MAIN__H_
    #define MAIN__H_

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <pcap.h>
#include <cstdio>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Ip_Tcp final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char data[256];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Forward_Packet final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Backward_Packet final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char msg[100];
};
#pragma pack(pop)

void usage(void);
void get_info(char * dev, Mac * mac, Ip * ip);
int find_target(char * data, char * target_pattern, size_t data_size);
int forward(pcap_t * handle,
    const u_char * packet, Ip_Tcp * ip_tcp, int size, int data_size, Mac mac_add);
int backward(pcap_t * handle,
    const u_char * packet, Ip_Tcp * ip_tcp, int packet_size, int data_size, Mac mac_add, int my_socket);
#endif