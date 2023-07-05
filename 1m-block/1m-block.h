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

#define MAX_URL_LENGTH 100
#define MAX_NUM_URLS 865000

char urls_db[MAX_NUM_URLS][MAX_URL_LENGTH];
char line[MAX_URL_LENGTH + 2];

int block_flag = 0;
int num_urls = 0;