#ifndef MAIN__H_
    #define MAIN__H_

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include <list>
#include <pthread.h>
#include "ip.h"

typedef struct Packet_struct {
    Mac sender_mac, target_mac;
    Ip sender_ip, target_ip;
}
Info;

// Get MAC and IP for a device.
Mac find_mac(Ip Ip);
void find_mac_add(Ip ip, Mac mac);
void get_attacker_info(char * dev, Mac * mac, Ip * ip);
void get_sender_info(Mac eth_smac, Ip arp_sip, Ip arp_tip);
void attack(Mac eth_dmac, Mac eth_smac, Ip arp_sip, Mac eth_tmac, Ip arp_tip);
int recover(EthHdr * eth_packet, Info info);
void *attack_after(void	*arg);
void *attack_init(void *arg);
//void sigint_handler(int signo);
void usage(void);
int relay(EthHdr * eth_packet, Info info);
#pragma pack(push, 1)

struct IPv4_hdr final {
    uint8_t version: 4;
    uint8_t IHL: 4;
    uint8_t Ip_tos;
    uint16_t Ip_total_length;
    uint8_t dummy[4];
    uint8_t TTL;
    uint8_t Protocol;
    uint8_t dummy2[2];
    Ip sip;
    Ip dip;
};

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IPv4_hdr ip_;
};

#pragma pack(pop)

Ip attacker_ip;
Mac attacker_mac;
EthArpPacket packet;
std::map < Ip, Mac > infomap;
std::list < Info > info_list;
pthread_mutex_t RecievePacketMutex = PTHREAD_MUTEX_INITIALIZER;
pcap_t * handle;

#endif