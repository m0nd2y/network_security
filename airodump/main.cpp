#include "main.h"


int main(int argc, char * argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char herror[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1, herror);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, herror);
        return -1;
    }
    struct pcap_pkthdr * header;
    const u_char * Packet;

    while (1) {
        int res = pcap_next_ex(handle, & header, & Packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // fix read thing ~~~
        RadiotapHeader * radiotap_header = (struct RadiotapHeader * ) Packet;
        BeaconHeader * beacon_header = (struct BeaconHeader * )(Packet + radiotap_header -> it_len);
        if (beacon_header -> frame_control != 0x80) {
            continue;
        }

        if (beacon_num.find(beacon_header -> bssid) == beacon_num.end()) {
            int num = 1;
            std::string SSID(beacon_header -> ssid, beacon_header -> len);
            beacon_num.insert({
                beacon_header -> bssid,
                num
            });
            essid_map.insert({
                beacon_header -> bssid,
                SSID
            });
        } else
            beacon_num[beacon_header -> bssid] += 1;

        for (auto itr = beacon_num.begin(); itr != beacon_num.end(); itr++) {
            printf("BSSID: %s\t", std::string(itr -> first).data());
            printf("Beacons: %d\t", itr -> second);
            printf("ESSID: %s\n", essid_map[itr -> first].c_str());
            printf("--------------------------------------------------\n");
        }

    }
    pcap_close(handle);
    return 0;
}