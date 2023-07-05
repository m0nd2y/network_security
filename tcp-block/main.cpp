#include "main.h"

pthread_mutex_t RecievePacketMutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char * argv[]) {
    pcap_t * handle;
    Mac sender_mac;
    Ip sender_ip;
    int my_socket;
    struct EthHdr * eth_packet;
    EthIpPacket * eth_ip_packet;
    Ip_Tcp * ip_tcp;
    int data_size;

    if ((argc != 3)) {
        usage();
        return -1;
    }

    char * dev = argv[1];
    char * target_pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    get_info(dev, & sender_mac, & sender_ip);
    printf("sender_mac: %s\n", std::string(sender_mac).data());
    printf("sender_ip: %s\n", std::string(sender_ip).data());

    int optval = 1;
    my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (my_socket < 0) {
        fprintf(stderr, "Error: socket failed\n");
        exit(1);
    }
    setsockopt(my_socket, IPPROTO_IP, IP_HDRINCL, (int * ) & optval, sizeof(int));

    while (1) {
        struct pcap_pkthdr * header;
        const u_char * packet;
        pthread_mutex_lock( & RecievePacketMutex);
        int res = pcap_next_ex(handle, & header, & packet);
        pthread_mutex_unlock( & RecievePacketMutex);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("(error) return %d(%s)\n", res, pcap_geterr(handle));
            return 0;
        }

        eth_packet = (struct EthHdr * ) packet;
        eth_ip_packet = (EthIpPacket * ) packet;
        if (eth_packet -> type() != EthHdr::Ip4 || eth_ip_packet -> ip_.p() != IpHdr::Tcp)
            continue;

        ip_tcp = (struct Ip_Tcp * ) packet;
        data_size = ip_tcp -> ip_.len() - ip_tcp -> ip_.hl() * 4 - ip_tcp -> tcp_.off() * 4;

        if (data_size > 0) {
            if (find_target(ip_tcp -> data, target_pattern, data_size)) {
                if (ip_tcp -> tcp_.sport() == 80 || ip_tcp -> tcp_.dport() == 80) {
                    if (!forward(handle, packet, ip_tcp, header -> caplen, data_size, sender_mac)) {
                        printf("[error] HTTP Foward Pacekct\n");
                        exit(-1);
                    }

                    if (!backward(handle, packet, ip_tcp, header -> caplen, data_size, sender_mac, my_socket)) {
                        printf("[error] HTTPbackward Pacekct\n");
                        exit(-1);
                    }
                } else if (ip_tcp -> tcp_.sport() == 443 || ip_tcp -> tcp_.dport() == 443) {
                    if (!forward(handle, packet, ip_tcp, header -> caplen, data_size, sender_mac)) {
                        printf("[error] HTTPS Foward Pacekct\n");
                        exit(-1);
                    }

                    if (!backward(handle, packet, ip_tcp, header -> caplen, data_size, sender_mac, my_socket)) {
                        printf("[error] HTTPS backward Pacekct\n");
                        exit(-1);
                    }
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}