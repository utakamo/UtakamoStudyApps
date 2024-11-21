#ifndef _H_IOCTL_TOOL_
#define _H_IOCTL_TOOL_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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
#define SUPPORT_SET_INTERFACE_LINK      // SIOCSIFLINK
#define SUPPORT_LIST_NETWORK_INTERFACES // SIOCGIFCONF
#define SUPPORT_GET_INTERFACE_FLAGS     // SIOCGIFFLAGS
#define SUPPORT_SET_INTERFACE_FLAGS     // SIOCSIFFLAGS

/********************************/
/*      Address operations      */
/********************************/
#define SUPPORT_GET_INTERFACE_IP        // SIOCGIFADDR
#define SUPPORT_SET_INTERFACE_IP        // SIOCSIFADDR 
#define SUPPORT_GET_DEST_ADDR           // SIOCGIFDSTADDR
#define SUPPORT_SET_DEST_ADDR           // SIOCSIFDSTADDR


#define ERR_SOCKET          1
#define ERR_INET_PTON       2
#define ERR_INET_PTON_DST   3
#define ERR_INET_PTON_GT    4
#define ERR_INET_PTON_MASK  5
#define ERR_IOCTL           6

#define MAX_INTERFACES      128

// Routing operations 
int add_route(const char *, const char *, const char *, const char *);
int delete_route(const char *, const char *, const char *);
int handle_rtmsg(char *, size_t);

// Network interface operations
int get_interface_name(int, char *, size_t);
int set_interface_link(const char *, int);
int list_network_interfaces(char *, size_t);
int get_interface_flags(const char *);
int set_interface_flags(const char *, short, short);

// Address operations
int get_interface_ip(const char *);
int set_interface_ip(const char *, const char *);
int get_dest_addr(const char *);
int set_dest_addr(const char *, const char *);
#endif