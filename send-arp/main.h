#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

void get_attacker_info(char *dev, Mac *mac, Ip *ip);