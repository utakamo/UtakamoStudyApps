#ifndef _H_IOCTL_TOOL_
#define _H_IOCTL_TOOL_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>


/********************************/
/*      Routing operations      */
/********************************/
#define SUPPORT_ADD_ROUTE               // SIOCADDRT
#define SUPPORT_DELETE_ROUTE            // SIOCDELRT
#define SUPPORT_HANDLE_RTMSG            // SIOCRTMSG

/********************************************/
/*      Network interface operations        */
/********************************************/
#define SUPPORT_GET_INTERFACE_NAME      // SIOCGIFNAME
#define SUPPORT_SET_IF_LINK             // SIOCSIFLINK
#define SUPPORT_LIST_IF                 // SIOCGIFCONF
#define SUPPORT_GET_INTERFACE_FLAGS     // SIOCGIFFLAGS
#define SUPPORT_SET_INTERFACE_FLAGS     // SIOCSIFFLAGS

/********************************/
/*      Address operations      */
/********************************/
#define SUPPORT_GET_INTERFACE_IP        // SIOCGIFADDR
#define SUPPORT_SET_INTERFACE_IP        // SIOCSIFADDR 
#define SUPPORT_GET_DEST_ADDR           // SIOCGIFDSTADDR
#define SUPPORT_SET_DEST_ADDR           // SIOCSIFDSTADDR
#define SUPPORT_GET_BCAST_ADDR          // SIOCGIFBRDADDR
#define SUPPORT_GET_NETMASK             // SIOCGIFNETMASK
#define SUPPORT_SET_NETMASK             // SIOCSIFNETMASK


/****************************************************/
/*      Other interface attribute operations        */
/****************************************************/
#define SUPPORT_GET_MTU                 // SIOCGIFMTU
#define SUPPORT_SET_MTU                 // SIOCSIFMTU
#define SUPPORT_GET_MAC_ADDR            // SIOCGIFHWADDR
#define SUPPORT_SET_MAC_ADDR            // SIOCSIFHWADDR

/****************************/
/*      ARP Operation       */
/****************************/
#define SUPPORT_DELETE_ARP_ENTRY        // SIOCDARP 
#define SUPPORT_GET_ARP_ENTRY           // SIOCGARP 
#define SUPPORT_SET_ARP_ENTRY           // SIOCSARP 

/****************************/
/*      RARP Operation      */
/****************************/
#define SUPPORT_DELETE_RARP_ENTRY       // SIOCDRARP
#define SUPPORT_GET_RARP_ENTRY          // SIOCGRARP
#define SUPPORT_SET_RARP_ENTRY          // SIOCSRARP

/****************************************************/
/*       Interface Info Operation for debug         */
/****************************************************/
#define SUPPORT_GET_IF_MAP              // SIOCGIFMAP
#define SUPPORT_SET_IF_MAP              // SIOCSIFMAP

#define ERR_SOCKET          1
#define ERR_INET_PTON       2
#define ERR_INET_PTON_DST   3
#define ERR_INET_PTON_GT    4
#define ERR_INET_PTON_MASK  5
#define ERR_IOCTL           6
#define ERR_MAC_FORMAT      7

#define MAX_INTERFACES      128

#define MAX_IFNAME_LEN      256

typedef struct if_list {
    char name[IFNAMSIZ];
    char ipv4_addr[INET_ADDRSTRLEN];
    char ipv6_addr[INET6_ADDRSTRLEN];
} if_list;

// Routing operations 
int add_route(const char *, const char *, const char *, const char *);
int delete_route(const char *, const char *, const char *);
int handle_rtmsg(char *, size_t);

// Network interface operations
int get_interface_name(int, char *, size_t);
int set_if_link(const char *, int);
int list_if(if_list *, int);
int get_interface_flags(const char *);
int set_interface_flags(const char *, short, short);

// Address operations
int get_interface_ip(const char *);
int set_interface_ip(const char *, const char *);
int get_dest_addr(const char *);
int set_dest_addr(const char *, const char *);
int get_bcast_addr(const char *);

// Other interface attribute operations
int get_mtu(const char *);
int set_mtu(const char *, int); 
int get_mac_addr(const char *);
int set_mac_addr(const char *, const char *);

// ARP Operation
int delete_arp_entry(const char *);
int get_arp_entry(const char *);
int set_arp_entry(const char *, const char *, const char *);

// RARP Operation
int delete_rarp_entry(const char *);
int get_rarp_entry(const char *);
int set_rarp_entry(const char *, const char *);

// Interface Info Operation for debug
int get_if_map(const char *);
int set_if_map(const char *, struct ifmap *);
int get_tx_que_len(const char *);
#endif