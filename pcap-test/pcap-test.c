#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		if (!is_ip(packet) || !is_tcp(packet + sizeof(struct libnet_ethernet_hdr)))
			continue;
		printf("===================================\n");
		printf("[ETH]\n");
		print_eth(packet);

		printf("[IP]\n");
		print_ip(packet + sizeof(struct libnet_ethernet_hdr));

		printf("[TCP]\n");
		print_tcp(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip4_hdr));

		printf("[DATA]\n");
		print_data(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr));
	}

	pcap_close(pcap);
}

// check is it ip
int is_ip(const u_char* packet)
{
	struct libnet_ethernet_hdr *target = (struct libnet_ethernet_hdr *) packet;
	//printf("%x\n", (ntohs(target->ether_type)));
	if ((ntohs(target->ether_type)) != 0x0800)
		return (0);
	return (1);
}

// check is it tcp
int is_tcp(const u_char* packet)
{
	struct ip4_hdr *target = (struct ip4_hdr *) packet;
	//printf("%x\n", (ntohs(target->Protocol)));
	if ((target->Protocol) != 0x06)
		return (0);
	return (1);
}

// print_eth_info
void print_eth(const u_char* packet)
{
	struct libnet_ethernet_hdr *target = (struct libnet_ethernet_hdr *) packet;
	printf("[ether_dhost] : %02x.%02x.%02x.%02x.%02x.%02x\n", target->ether_dhost[0], target->ether_dhost[1], target->ether_dhost[2], target->ether_dhost[3], target->ether_dhost[4], target->ether_dhost[5]);
	printf("[ether_shost] : %02x.%02x.%02x.%02x.%02x.%02x\n", target->ether_shost[0], target->ether_shost[1], target->ether_shost[2], target->ether_shost[3], target->ether_shost[4], target->ether_shost[5]);
	printf("\n");
}

// print_ip_info
void print_ip(const u_char* packet)
{
	struct ip4_hdr *target = (struct ip4_hdr *) packet;
	printf("[IP_src_mac] : %d.%d.%d.%d\n", target->IP_src_mac[0], target->IP_src_mac[1], target->IP_src_mac[2], target->IP_src_mac[3]);
	printf("[IP_dst_mac] : %d.%d.%d.%d\n", target->IP_dst_mac[0], target->IP_dst_mac[1], target->IP_dst_mac[2], target->IP_dst_mac[3]);
	printf("\n");
	packet_length = ntohs(target->Total_length);
}

// print_tcp_info
void print_tcp(const u_char* packet)
{
	struct tcp_hdr *target = (struct tcp_hdr *) packet;
	printf("[tcp_Source_port] : %d\n", ntohs(target->Source_port));
	printf("[tcp_Destination_port] : %d\n", ntohs(target->Destination_port));
	printf("\n");
}

// print_data_info
void print_data(const u_char* packet)
{
	struct Data *target = (struct Data *) packet;
	if (packet_length > sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr))
	{
		for (int i = 0; i < 10; i++)
		{
			if (packet_length <= i + sizeof(struct libnet_ethernet_hdr) + sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr))
				break;
			if (i == 0)
				printf("[data] : ");
			printf("%x ", target->data[i]);
		}
	}
	else
	{
		printf("NO DATA");
	}
	printf("\n");
}

