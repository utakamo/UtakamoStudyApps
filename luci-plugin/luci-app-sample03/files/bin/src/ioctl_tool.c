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
* char message[1024];
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

#ifdef SUPPORT_SET_INTERFACE_LINK
/*
* Change the “link” setting for the interface.
* This function is used internally to control the behavior associated with a particular network device (e.g., virtual device).
* To check the results of the link configuration, the following commands can be used
* ex) ip link show eth0
*
* usage:
* set_interface_link("eth0", 1);
*/
int set_interface_link(const char *ifname, int link_index) {

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

#ifdef SUPPORT_LIST_NETWORK_INTERFACES
/*
* Get a list of network interfaces.
*
* usage:
* char if_list[1024];
* list_network_interfaces(if_list, sizeof(if_list));
*/
int list_network_interfaces(char* if_list, size_t if_list_len) {

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
        char ip_address[INET_ADDRSTRLEN];
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr[i].ifr_addr;

        printf("Interface: %s\n", ifr[i].ifr_name);

        if (inet_ntop(AF_INET, &addr->sin_addr, ip_address, sizeof(ip_address)) == NULL) {
            perror("inet_ntop");
        } else {
            printf("  IP Address: %s\n", ip_address);
        }
    }

    close(sockfd);

    return 0;
}
#endif

#ifdef SUPPORT_GET_INTERFACE_FLAGS
/*
* Get network interface flags.
*
* usage:
* 
*/
int get_interface_flags(const char *ifname) {

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

    printf("Flags for interface %s: 0x%x\n", ifname, flags);

    if (flags & IFF_UP) printf("  Interface is up\n");
    if (flags & IFF_BROADCAST) printf("  Supports broadcast\n");
    if (flags & IFF_LOOPBACK) printf("  Loopback interface\n");
    if (flags & IFF_POINTOPOINT) printf("  Point-to-point link\n");
    if (flags & IFF_RUNNING) printf("  Interface is running\n");
    if (flags & IFF_NOARP) printf("  No ARP protocol\n");
    if (flags & IFF_PROMISC) printf("  Promiscuous mode\n");

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

#ifdef SUPPORT_GET_INTERFACE_IP
/*
*
*
*
*/
int get_interface_ip(const char *ifname) {
    int sockfd;
    struct ifreq ifr;

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
    printf("IP address of %s: %s\n", ifname, inet_ntoa(ipaddr->sin_addr));

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
int get_dest_addr(const char *ifname) {

    int sockfd;
    struct ifreq ifr;

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
    printf("Destination address of %s: %s\n", ifname, inet_ntoa(dstaddr->sin_addr));

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

int main() {

    //add_route("192.168.1.0", "192.168.1.1", "255.255.255.0", "eth0");
    //delete_route("192.168.1.0", "255.255.255.0", "eth0");

    //char message[1024];
    //handle_rtmsg(message, sizeof(message));
    //printf("%s\n", message);

    //char ifname[256];
    //get_interface_name(1, ifname, sizeof(ifname));
    //printf("%s\n", ifname);

    //set_interface_link("eth0", 1);

    //char if_list[1024];
    //list_network_interfaces(if_list, sizeof(if_list));

    //get_interface_flags("eth0");
    set_interface_flags("eth", 0x01, 0x0);
}
