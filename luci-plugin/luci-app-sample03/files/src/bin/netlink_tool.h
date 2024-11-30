#ifndef _NETLINK_TOOL_H_
#define _NETLINK_TOOL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include "common.h"

#define BUFFER_SIZE 8192

typedef struct netlink_if_list {
    int index;
    char ifname[IFNAMSIZ];
} netlink_if_list;

int netlink_list_if(netlink_if_list *, int);

#endif
