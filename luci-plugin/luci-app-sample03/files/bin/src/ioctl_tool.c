#include "ioctl_tool.h"

#ifdef SUPPORT_ADD_ROUTE
/*
* IOCTL: SIOCADDRT
* This process is equivalent to the ip route add or route add command in Linux commands.
* These commands are used to add new routes to the kernel routing table.
* The result of this function can be checked with "ip route show" command.
*
* usage: add_route("192.168.1.0", "192.168.1.1", "255.255.255.0", "eth0");
* ---> ip route add 192.168.1.0/24 via 192.168.1.1 dev eth0
*/
int add_route(const char *destination, const char *gateway, const char *netmask, const char *interface) {

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
    if (inet_pton(AF_INET, destination, &addr->sin_addr) <= 0) {
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
    route.rt_dev = (char *)interface;

    if (ioctl(sockfd, SIOCADDRT, &route) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_DELETE_ROUTE
/*
* This process is equivalent to the ip route delete or route delete command in Linux commands.
* These commands are used to remove the target route from the kernel routing table.
* The result of this function can be checked with the ip route show command.
*
* usage: delete_route("192.168.1.0", "255.255.255.0", "eth0");
* ---> ip route del 192.168.1.0/24 dev eth0
*/
int delete_route(const char *destination, const char *netmask, const char *interface) {
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
    if (inet_pton(AF_INET, destination, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_DST;
    }

    addr = (struct sockaddr_in *)&route.rt_genmask;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, netmask, &addr->sin_addr) <= 0) {
        close(sockfd);
        return ERR_INET_PTON_MASK;
    }

    route.rt_dev = (char *)interface;

    if (ioctl(sockfd, SIOCDELRT, &route) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_HANDLE_RTMSG
/*
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
#endif

#ifdef SUPPORT_GET_INTERFACE_NAME
/*
* Obtain its name from the interface number.
* 
* usage:
* char ifname[256];
* get_interface_name(1, ifname, sizeof(ifname));
*/
int get_interface_name(int if_index, char *ifname, size_t name_len) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_ifindex = if_index;

    if (ioctl(sockfd, SIOCGIFNAME, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    strncpy(ifname, ifr.ifr_name, name_len - 1);
    ifname[name_len - 1] = '\0';

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_SET_IF_LINK
/*
* Change the “link” setting for the interface.
* This function is used internally to control the behavior associated with a particular network device (e.g., virtual device).
* To check the results of the link configuration, the following commands can be used
* ex) ip link show eth0
*
* usage:
* set_if_link("eth0", 1);
*/
int set_if_link(const char *ifname, int link_index) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ifr.ifr_ifindex = link_index;

    if (ioctl(sockfd, SIOCSIFLINK, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_LIST_IF
/*
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
#endif

#ifdef SUPPORT_GET_IF_FLAGS
/*
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
#endif

#ifdef SUPPORT_SET_INTERFACE_FLAGS
/*
* Set network interface flags.
* 
* usage:
* set_interface("eth0", 0x1, 0x0);
*/
int set_interface_flags(const char *ifname, short flags_to_set, short flags_to_clear) {
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

    printf("Current flags for interface %s: 0x%x\n", ifname, ifr.ifr_flags);

    ifr.ifr_flags |= flags_to_set;
    ifr.ifr_flags &= ~flags_to_clear;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    printf("Updated flags for interface %s: 0x%x\n", ifname, ifr.ifr_flags);

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_GET_IF_IPV4
/*
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
#endif

#ifdef SUPPORT_SET_INTERFACE_IP
/*
* 
*
*
*/
int set_interface_ip(const char *ifname, const char *ip_address) {

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
#endif

#ifdef SUPPORT_GET_DEST_ADDR
/*
*
*
*
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
#endif

#ifdef SUPPORT_SET_DEST_ADDR
/*
*
*
*
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

    printf("Destination address %s set successfully on interface %s\n", dest_addr, ifname);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_BCAST_ADDR
/*
* 
* 
* 
*/
int get_bcast_addr(const char *ifname) {

    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *broadcast_addr;

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
    printf("Broadcast address for interface %s: %s\n",
           ifname, inet_ntoa(broadcast_addr->sin_addr));

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_SET_BCAST_ADDR
/*
*
*
*
*
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

    printf("Broadcast address %s set successfully on interface %s\n", bcast_addr, ifname);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_NETMASK
/*
*
*
*
*
*/
int get_netmask(const char *ifname) {

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
    printf("Netmask for interface %s: %s\n",
           ifname, inet_ntoa(netmask_addr->sin_addr));

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_SET_NETMASK
/*
*
*
*
*
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
#endif

#ifdef SUPPORT_GET_MTU
/*
*
*
*
*/
int get_mtu(const char *ifname) {

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

    printf("MTU for interface %s: %d\n", ifname, ifr.ifr_mtu);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_SET_MTU
/*
*
*
*
*
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

    printf("MTU set to %d for interface %s\n", mtu, ifname);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_MAC_ADDR
/*
*
*
*
*
*/
int get_mac_addr(const char *ifname) {

    int sockfd;
    struct ifreq ifr;

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

    printf("MAC address for interface %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_SET_MAC_ADDR
/*
*
*
*
*/
int set_mac_addr(const char *ifname, const char *new_mac_addr) {

    int sockfd;
    struct ifreq ifr;
    unsigned char mac[6];

    if (sscanf(new_mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format: %s\n", new_mac_addr);
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

    printf("MAC address set to %s for interface %s\n", new_mac_addr, ifname);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_DELETE_ARP_ENTRY
/*
*
*
*
*
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

    printf("ARP entry for %s has been deleted successfully.\n", ip_addr);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_ARP_ENTRY
/*
*
*
*
*/
int get_arp_entry(const char *ip_addr) {

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

    if (ioctl(sockfd, SIOCGARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    unsigned char *mac = (unsigned char *)req.arp_ha.sa_data;
    printf("IP Address: %s\n", ip_addr);
    printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    printf("Flags: 0x%x\n", req.arp_flags);
    if (req.arp_flags & ATF_COM) {
        printf("  - Entry is complete\n");
    }
    if (req.arp_flags & ATF_PERM) {
        printf("  - Entry is permanent\n");
    }
    if (req.arp_flags & ATF_PUBL) {
        printf("  - Entry is published\n");
    }
    if (req.arp_flags & ATF_USETRAILERS) {
        printf("  - Use trailers\n");
    }

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_SET_ARP_ENTRY
/*
*
*
*
*
*/
int set_arp_entry(const char *ip_addr, const char *mac_addr, const char *interface) {

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

    strncpy(req.arp_dev, interface, sizeof(req.arp_dev) - 1);

    req.arp_flags = ATF_COM | ATF_PERM;

    if (ioctl(sockfd, SIOCSARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    printf("Successfully added ARP entry for IP: %s\n", ip_addr);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_DELETE_RARP_ENTRY
/*
*
*
*
*
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

    printf("Successfully deleted RARP entry for IP: %s\n", ip_addr);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_RARP_ENTRY
/*
*
*
*
*
*/
int get_rarp_entry(const char *ip_addr) {

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
        return ERR_SOCKET;
    }

    if (ioctl(sockfd, SIOCGRARP, &req) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    printf("RARP entry for IP: %s\n", ip_addr);
    printf("Hardware address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", (unsigned char)req.arp_ha.sa_data[i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    printf("Flags: 0x%x\n", req.arp_flags);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_SET_RARP_ENTRY
/*
*
*
*
*
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

    printf("Successfully set RARP entry for IP: %s with MAC: %s\n", ip_addr, mac_addr);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_IF_MAP
/*
*
*
*
*
*/
int get_if_map(const char *ifname) {

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
    printf("Interface: %s\n", ifname);
    printf("  mem_start: 0x%lx\n", map->mem_start);
    printf("  mem_end:   0x%lx\n", map->mem_end);
    printf("  base_addr: 0x%x\n", map->base_addr);
    printf("  irq:       %d\n", map->irq);
    printf("  dma:       %d\n", map->dma);
    printf("  port:      %d\n", map->port);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_SET_IF_MAP
/*
*
*
*
*/
int set_if_map(const char *ifname, struct ifmap *new_map) {

    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return ERR_SOCKET;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    memcpy(&ifr.ifr_map, new_map, sizeof(struct ifmap));

    if (ioctl(sockfd, SIOCSIFMAP, &ifr) < 0) {
        close(sockfd);
        return ERR_IOCTL;
    }

    printf("Hardware parameters updated for interface: %s\n", ifname);

    close(sockfd);
    return 0;
}
#endif

#ifdef SUPPORT_GET_TX_QUE_LEN
/*
*
*
*
*/
int get_tx_que_len(const char *ifname) {

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

    printf("Interface: %s\n", ifname);
    printf("Transmit Queue Length: %d\n", ifr.ifr_qlen);

    close(sockfd);

    return 0;
}
#endif

/*
int main() {

    //add_route("192.168.1.0", "192.168.1.1", "255.255.255.0", "eth0");
    //delete_route("192.168.1.0", "255.255.255.0", "eth0");

    //char message[1024];
    //handle_rtmsg(message, sizeof(message));
    //printf("%s\n", message);

    //char ifname[256];
    //get_interface_name(1, ifname, sizeof(ifname));
    //printf("%s\n", ifname);

    //set_if_link("eth0", 1);

    //char if_list[1024];
    //list_if(if_list, sizeof(if_list));

    //get_if_flags("eth0");
    //set_interface_flags("eth", 0x01, 0x0);
}
*/