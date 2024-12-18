/*
 * Copyright (C) 2024 utakamo <contact@utakamo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ioctl_tool.h"

/*
* IOCTL: SIOCADDRT
* This process is equivalent to the ip route add or route add command in Linux commands.
* These commands are used to add new routes to the kernel routing table.
* The result of this function can be checked with "ip route show" command.
*
* usage: add_route("192.168.1.0", "192.168.1.1", "255.255.255.0", "eth0");
* ---> ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0
*/
int add_route(const char *dest, const char *gateway, const char *netmask, const char *ifname) {

    int sockfd;
    struct rtentry route;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&route, 0, sizeof(route));

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, dest, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_DST;
    }

    addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, gateway, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_GT;
    }

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_MASK;
    }

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char *)ifname;

    if (ioctl(sockfd, SIOCADDRT, &route) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCDELRT
* This process is equivalent to the ip route delete or route delete command in Linux commands.
* These commands are used to remove the target route from the kernel routing table.
* The result of this function can be checked with the ip route show command.
*
* usage: delete_route("192.168.1.0", "255.255.255.0", "eth0");
* ---> ip route del 192.168.1.0/24 dev eth0
*/
int delete_route(const char *dest, const char *netmask, const char *ifname) {

    int sockfd;
    struct rtentry route;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&route, 0, sizeof(route));

    addr = (struct sockaddr_in *)&route.rt_dst;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, dest, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_DST;
    }

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_MASK;
    }

    route.rt_dev = (char *)ifname;

    if (ioctl(sockfd, SIOCDELRT, &route) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCRTMSG
* A low-level ioctl request used to retrieve or inform the kernel of internal routing information.
* However, unlike normal network configuration, this request is rarely used. 
* It is also ambiguous in use and meaning, and may involve kernel- or specific driver-dependent behavior.
*
* usage:
* char message[256];
* handle_rtmsg(message, sizeof(message))
*/
int handle_rtmsg(char *msg, size_t msg_len) {

    int sockfd;
    int result;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(msg, 0, msg_len);

    result = ioctl(sockfd, SIOCRTMSG, msg);

    if (result < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCGIFNAME
* Get its name from the interface number.
* 
* usage:
* char ifname[256];
* get_ifname_from_idx(1, ifname, sizeof(ifname));
*/
int get_ifname_from_idx(int if_idx, char *ifname, size_t name_len) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_ifindex = if_idx;

    if (ioctl(sockfd, SIOCGIFNAME, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    strncpy(ifname, ifr.ifr_name, name_len - 1);
    ifname[name_len - 1] = '\0';

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFLINK
* Change the “link” setting for the interface.
* This function is used internally to control the behavior associated with a particular network device (e.g., virtual device).
* To check the results of the link configuration, the following commands can be used
* ex) ip link show eth0
*
* usage:
* set_if_link("eth0", 1);
*/
int set_if_link(const char *ifname, int link_idx) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ifr.ifr_ifindex = link_idx;

    if (ioctl(sockfd, SIOCSIFLINK, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCGIFCONF
* Get a list of network interfaces.
*
* usage:
* char if_list[1024];
* list_if(if_list, sizeof(if_list));
*/
int list_if(if_list *list, int max_if_num) {

    int sockfd;
    struct ifconf ifc;
    struct ifreq ifr[MAX_INTERFACES];
    int i, num_interfaces;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    ifc.ifc_len = sizeof(ifr);
    ifc.ifc_req = ifr;

    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    num_interfaces = ifc.ifc_len / sizeof(struct ifreq);

    for (i = 0; i < num_interfaces; i++) {
        char ip_addr[INET_ADDRSTRLEN];
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr[i].ifr_addr;

        if (i >= max_if_num) {
            break;
        }

        snprintf(list[i].name, IFNAMSIZ, "%s", ifr[i].ifr_name);

        //printf("Interface: %s\n", ifr[i].ifr_name);

        if (inet_ntop(AF_INET, &addr->sin_addr, ip_addr, sizeof(ip_addr)) == NULL) {
            snprintf(list[i].ipv4_addr, INET_ADDRSTRLEN, "none");
        } else {
            snprintf(list[i].ipv4_addr, INET_ADDRSTRLEN, "%s", ip_addr);
            //printf("  IP Address: %s\n", ip_addr);
        }
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCGIFFLAGS
* Get network interface flags.
*
* usage:
* flag_info info;
* get_if_flags("eth0", &info);
*/
int get_if_flags(const char *ifname, flag_info *info) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    short flags = ifr.ifr_flags;

    snprintf(info->flag, MAX_FLAG_STRING, "0x%x", flags);

    int i;
    for (i = 0; i < MAX_FLAG_NUM; i++) {
        memset(info->message[i], '\0', MAX_FLAG_MESSAGE);
    }

    int item = 0;
    if (flags & IFF_UP) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Interface is up (IFF_UP)");
    if (flags & IFF_BROADCAST) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Supports broadcast (IFF_BROADCAST)");
    if (flags & IFF_LOOPBACK) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Loopback interface (IFF_LOOPBACK)");
    if (flags & IFF_POINTOPOINT) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Point-to-point link (IFF_POINTOPOINT)");
    if (flags & IFF_RUNNING) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Interface is running (IFF_RUNNING)");
    if (flags & IFF_NOARP) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "No ARP protocol (IFF_NOARP)");
    if (flags & IFF_PROMISC) snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Promiscuous mode (IFF_PROMISC)");

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFFLAGS
* Set network interface flags.
* 
* usage:
* char flag[16];
* set_interface("eth0", 0x1, 0x0);
*/
int set_if_flags(const char *ifname, short flags_to_set, short flags_to_clear) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ifr.ifr_flags |= flags_to_set;
    ifr.ifr_flags &= ~flags_to_clear;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCGIFADDR
* Get the IPv4 address of an interface.
*
* usage:
* char ipv4_addr[INET_ADDRSTRLEN];
* get_if_ipv4("eth0", ipv4_addr, sizeof(ipv4_addr));
*/
int get_if_ipv4(const char *ifname, char *ipv4_addr, size_t addr_len) {

    int sockfd;
    struct ifreq ifr;

    memset(ipv4_addr, '\0', addr_len);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    snprintf(ipv4_addr, addr_len, "%s", inet_ntoa(ipaddr->sin_addr));

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFADDR
* Set IPv4 address on the target interface.
*
* usage:
* set_if_ipv4("eth0", "192.168.1.2");
*/
int set_if_ipv4(const char *ifname, const char *ip_address) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    sin.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_address, &sin.sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCGIFDSTADDR
* Get the destination address (IPv4) of an interface
*
* usage:
* char dest_addr[INET_ADDRSTRLEN];
* get_dest_addr("eth0", dest_addr, sizeof(dest_addr));
*/
int get_dest_addr(const char *ifname, char *dest_addr, size_t addr_len) {

    int sockfd;
    struct ifreq ifr;

    memset(dest_addr, '\0', addr_len);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFDSTADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    struct sockaddr_in *dstaddr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    snprintf(dest_addr, addr_len, "%s", inet_ntoa(dstaddr->sin_addr));

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFDSTADDR
* Set the destination ip address on the target interface.
*
* usage:
* set_dest_addr("eth0", "192.168.2.1");
*/
int set_dest_addr(const char *ifname, const char *dest_addr) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    addr = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    addr->sin_family = AF_INET;

    if (inet_pton(AF_INET, dest_addr, &addr->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCSIFDSTADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFBRDADDR
* Get the broadcast address (IPv4) of an interface
* 
* usage:
* char bcast_addr[INET_ADDRSTRLEN];
* get_bcast_addr("eth0", bcast_addr, sizeof(bcast_addr));
*/
int get_bcast_addr(const char *ifname, char *bcast_addr, size_t addr_len) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *broadcast_addr;

    memset(bcast_addr, '\0', addr_len);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFBRDADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    broadcast_addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    snprintf(bcast_addr, addr_len, "%s", inet_ntoa(broadcast_addr->sin_addr));

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFBRDADDR
* Set the broadcast address on the target interface.
*
* usage:
* set_bcast_addr("eth0", "255.255.255.0")
*/
int set_bcast_addr(const char *ifname, const char *bcast_addr) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    addr->sin_family = AF_INET;

    if (inet_pton(AF_INET, bcast_addr, &addr->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFNETMASK
* Get the subnet mask of the target interface.
*
* usage:
* get_netmask("eth0");
*/
int get_netmask(const char *ifname, char* netmask, size_t netmask_len) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *netmask_addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    netmask_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    snprintf(netmask, netmask_len, "%s", inet_ntoa(netmask_addr->sin_addr));

    close(sockfd);

    return 0;
}

/*
* IOCTL: SIOCSIFNETMASK
* Set the subnet mask on the target interface.
*
* usage:
* set_netmask("eth0", "255.255.255.0");
*/
int set_netmask(const char *ifname, const char *netmask) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;

    if (inet_pton(AF_INET, netmask, &addr->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    printf("Netmask %s set successfully on interface %s\n", netmask, ifname);

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFMTU
* Get the mtu of target interface
*
* usage:
* int mtu;
* get_mtu("eth0", &mtu);
*/
int get_mtu(const char *ifname, int *mtu) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    *mtu = ifr.ifr_mtu;

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCSIFMTU
* Set the mtu on the target interface.
*
* usage:
* set_mtu("eth0", 1500);
*/
int set_mtu(const char *ifname, int mtu) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ifr.ifr_mtu = mtu;

    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFHWADDR
* Get the mac address of an interface.
*
* usage:
* char mac_addr[64];
* get_mac_addr("eth0", mac_addr, sizeof(mac_addr));
*/
int get_mac_addr(const char *ifname, char *mac_addr, size_t addr_len) {

    int sockfd;
    struct ifreq ifr;

    memset(mac_addr, '\0', addr_len);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    snprintf(mac_addr, addr_len, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCSIFHWADDR
* Set the mac address on the target interface.
*
* usage:
* set_mac_addr("eth0", "AA:BB:CC:DD:EE:FF");
*/
int set_mac_addr(const char *ifname, const char *macaddr) {

    int sockfd;
    struct ifreq ifr;
    unsigned char mac[6];

    if (sscanf(macaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        return ERR_MAC_FORMAT;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    if (ioctl(sockfd, SIOCSIFHWADDR, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCDARP
* Delete the ARP entry for the specified IP address.
*
* usage:
* delete_arp_entry("192.168.1.2");
*/
int delete_arp_entry(const char *ip_addr) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCDARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGARP
* Get the ARP entry corresponding to the IP address of the neighbor device.
*
* usage:
* arp_entry_info info;
* get_arp_entry("192.168.1.1", &info);
*/
int get_arp_entry(const char *neigh_ip_addr, arp_entry_info *info) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, neigh_ip_addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCGARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    unsigned char *mac = (unsigned char *)req.arp_ha.sa_data;
    snprintf(info->mac_addr, 64, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    snprintf(info->flag, MAX_FLAG_STRING, "0x%x\n", req.arp_flags);

    int item = 0;

    if (req.arp_flags & ATF_COM) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is complete (ATF_COM)");
    }
    if (req.arp_flags & ATF_PERM) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is permanent (ATF_PERM)");
    }
    if (req.arp_flags & ATF_PUBL) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is published (ATF_PUBL)");
    }
    if (req.arp_flags & ATF_USETRAILERS) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Use trailers (ATF_USETRAILERS)");
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCSARP
* Set new arp entry
* 
* usage:
* set_arp_entry("eth0", "192.168.2.1", "aa:bb:cc:dd:ee:ff");
*/
int set_arp_entry(const char *ifname, const char *ip_addr, const char *mac_addr) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;
    unsigned char mac[ETH_ALEN];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        close(sockfd);
        return ERR_MAC_FORMAT;
    }
    memcpy(req.arp_ha.sa_data, mac, ETH_ALEN);
    req.arp_ha.sa_family = ARPHRD_ETHER;

    strncpy(req.arp_dev, ifname, sizeof(req.arp_dev) - 1);

    req.arp_flags = ATF_COM | ATF_PERM;

    if (ioctl(sockfd, SIOCSARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCDRARP
* Delete the RARP entry for the specified IP address.
* Note: Legacy
*
* usage:
* delete_rarp_entry("192.168.1.2");
*/
int delete_rarp_entry(const char *ip_addr) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    if (ioctl(sockfd, SIOCDRARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGRARP
* Get the corresponding IP address from the MAC address of the adjacent device.
* Note: Legacy
*
* usage:
* rarp_entry_info info;
* get_rarp_entry("AA:BB:CC:DD:EE:FF", &info);
*/
int get_rarp_entry(const char *neigh_mac_addr, rarp_entry_info *info) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    memcpy(req.arp_ha.sa_data, neigh_mac_addr, 6);
    req.arp_ha.sa_family = ARPHRD_ETHER;

    if (ioctl(sockfd, SIOCGRARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    sin = (struct sockaddr_in *)&req.arp_pa;
    inet_ntop(AF_INET, &sin->sin_addr, info->ip_addr, INET_ADDRSTRLEN);

    snprintf(info->flag, MAX_FLAG_STRING, "0x%x\n", req.arp_flags);

    int item = 0;

    if (req.arp_flags & ATF_COM) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is complete (ATF_COM)");
    }
    if (req.arp_flags & ATF_PERM) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is permanent (ATF_PERM)");
    }
    if (req.arp_flags & ATF_PUBL) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Entry is published (ATF_PUBL)");
    }
    if (req.arp_flags & ATF_USETRAILERS) {
        snprintf(info->message[item++], MAX_FLAG_MESSAGE, "Use trailers (ATF_USETRAILERS)");
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCSRARP
* Set the mapping between IP addresses and the MAC addresses of adjacent devices.
* Note: Legacy
*
* usage:
* get_rarp_entry("192.168.1.2", "AA:BB:CC:DD:EE:FF");
*/
int set_rarp_entry(const char *ip_addr, const char *mac_addr) {

    int sockfd;
    struct arpreq req;
    struct sockaddr_in *sin;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&req, 0, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_addr, &sin->sin_addr) != 1) {
        close(sockfd);
        return ERR_INET_PTON;
    }

    struct sockaddr *ha = &req.arp_ha;
    ha->sa_family = ARPHRD_ETHER;
    unsigned int mac[6];
    if (sscanf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        close(sockfd);
        return ERR_MAC_FORMAT;
    }
    for (int i = 0; i < 6; i++) {
        ha->sa_data[i] = (unsigned char)mac[i];
    }

    req.arp_flags = ATF_COM;

    if (ioctl(sockfd, SIOCSRARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFMAP
* Get the address mapping information of the target interface.
*
* usage:
* map_info info;
* get_if_map("eth0", &info);
*/
int get_if_map(const char *ifname, map_info *info) {

    int sockfd;
    struct ifreq ifr;
    struct ifmap *map;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFMAP, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    map = &ifr.ifr_map;
    snprintf(info->mem_start, 256, "0x%lx", map->mem_start);
    snprintf(info->mem_end, 256, "0x%lx", map->mem_end);
    snprintf(info->base_addr, 256, "0x%x", map->base_addr);
    info->irq = map->irq;
    info->dma = map->dma;
    info->port = map->port;

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCSIFMAP
* Set the address mapping information for the target interface.
*
* usage:
* struct ifmap map;
* map.mem_start = 0x0;
* map.mem_end   = 0x0;
* map.base_addr = 0xc00
* map.irq       = 10
* map.dma       = 0
* map.port      = 0
* set_if_map("eth", map);
*/
int set_if_map(const char *ifname, struct ifmap map) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    memcpy(&ifr.ifr_map, &map, sizeof(struct ifmap));

    if (ioctl(sockfd, SIOCSIFMAP, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);
    return 0;
}

/*
* IOCTL: SIOCGIFTXQLEN
* Get the information of the packet transmission queue of the target interface
* 
* usage:
* int qlen;
* get_tx_que_len("eth0", &qlen);
*/
int get_tx_que_len(const char *ifname, int *qlen) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFTXQLEN, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    *qlen = ifr.ifr_qlen;

    close(sockfd);

    return 0;
}