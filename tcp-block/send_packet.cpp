#include "main.h"

int forward(pcap_t * handle,
    const u_char * packet, Ip_Tcp * ip_tcp, int size, int data_size, Mac mac_add) {
    u_char * tmp = (u_char * ) malloc(size);
    memcpy(tmp, packet, size);
    Forward_Packet * forwardpacket = (Forward_Packet * ) tmp;

    forwardpacket -> eth_.smac_ = mac_add;
    forwardpacket -> eth_.dmac_ = ip_tcp -> eth_.dmac();
    forwardpacket -> ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    forwardpacket -> ip_.ttl_ = ip_tcp -> ip_.ttl();
    forwardpacket -> ip_.sum_ = htons(IpHdr::calcChecksum( & (forwardpacket -> ip_)));
    forwardpacket -> tcp_.seq_ = htonl(ip_tcp -> tcp_.seq() + data_size);
    forwardpacket -> tcp_.ack_ = ip_tcp -> tcp_.ack_;
    forwardpacket -> tcp_.off_rsvd_ = (sizeof(struct TcpHdr) / 4) << 4;
    forwardpacket -> tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
    forwardpacket -> tcp_.sum_ = htons(TcpHdr::calcChecksum( & (forwardpacket -> ip_), & (forwardpacket -> tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast <
        const u_char * > (forwardpacket), sizeof(struct Forward_Packet));
    if (res != 0)
        return (0);
    memset(tmp, 0, size);
    free(tmp);
    return (1);
}

int backward(pcap_t * handle,
    const u_char * packet, Ip_Tcp * ip_tcp, int size, int data_size, Mac mac_add, int my_socket) {
    u_char * tmp = (u_char * ) malloc(size);
    memcpy(tmp, packet, size);
    Backward_Packet * backwardpacket = (Backward_Packet * ) tmp;

    backwardpacket -> eth_.smac_ = mac_add;
    backwardpacket -> eth_.dmac_ = ip_tcp -> eth_.smac();

    backwardpacket -> ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr) + 55);
    backwardpacket -> ip_.ttl_ = 128;
    backwardpacket -> ip_.sip_ = ip_tcp -> ip_.dip_;
    backwardpacket -> ip_.dip_ = ip_tcp -> ip_.sip_;
    backwardpacket -> ip_.sum_ = htons(IpHdr::calcChecksum( & (backwardpacket -> ip_)));

    backwardpacket -> tcp_.sport_ = ip_tcp -> tcp_.dport_;
    backwardpacket -> tcp_.dport_ = ip_tcp -> tcp_.sport_;
    backwardpacket -> tcp_.seq_ = ip_tcp -> tcp_.ack_;
    backwardpacket -> tcp_.ack_ = htonl(ip_tcp -> tcp_.seq() + data_size);
    backwardpacket -> tcp_.off_rsvd_ = (sizeof(struct TcpHdr) / 4) << 4;
    backwardpacket -> tcp_.flags_ = TcpHdr::Fin | TcpHdr::Ack;
    memcpy(backwardpacket -> msg, "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n", 56);
    size += 56;
    backwardpacket -> tcp_.sum_ = htons(TcpHdr::calcChecksum( & (backwardpacket -> ip_), & (backwardpacket -> tcp_)));

    struct sockaddr_in sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = backwardpacket -> tcp_.dport_;
    sockaddr.sin_addr.s_addr = backwardpacket -> ip_.dip_;

    int res = sendto(my_socket, & (backwardpacket -> ip_), backwardpacket -> ip_.len(), 0, (struct sockaddr * ) & sockaddr, sizeof(sockaddr));
    if (res < 0)
        return (0);
    free(tmp);
    return (1);

}