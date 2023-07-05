#include <stdio.h>

#include <pcap.h>
#include <map>
#include "mac.h"
#include <iostream>

struct RadiotapHeader {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
};

struct BeaconHeader {
    uint16_t frame_control;
    uint16_t duration_id;
    Mac dest_addr;
    Mac src_addr;
    Mac bssid;
    uint16_t squence_num;
    //Mac bssid() {return bssid;}

    //fixed parameters
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;

    //tagged parameters
    uint8_t tag_num;
    uint8_t len;
    char ssid[100];
};

std::map < Mac, int > beacon_num;
std::map < Mac, std::string > essid_map;

void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}