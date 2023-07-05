#include "main.h"

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
    {
        *mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }

    if (0 == ioctl(fd, SIOCGIFADDR, &ifr))
    {
        *ip = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
    }
    close(fd);
    return;
}