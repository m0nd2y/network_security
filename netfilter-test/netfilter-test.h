#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "iphdr.h"
#include "tcphdr.h"
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#pragma pack(push, 1)
struct Ip_Tcp_Data final
{
    IpHdr ip_hdr;
    TcpHdr tcp_hdr;
	char data [1000];
};
#pragma pack(pop)

int block_flag = 0;
char * target;