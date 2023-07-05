#include "main.h"

void usage(void) {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int find_target(char * data, char * target_pattern, size_t data_size) {
    size_t target_pattern_len, data_len;
    int i = 0;

    if (! * target_pattern) {
        return (0);
    }
    target_pattern_len = strlen(target_pattern);
    data_len = strlen(data);
    if (data_len < target_pattern_len || data_size < target_pattern_len) {
        return (0);
    }
    while (i + target_pattern_len <= data_size) {
        if (data[i] == * target_pattern && !strncmp(data + i, target_pattern, target_pattern_len))
            return (1);
        i++;
    }
    return (0);
}

void get_info(char * dev, Mac * mac, Ip * ip) {
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