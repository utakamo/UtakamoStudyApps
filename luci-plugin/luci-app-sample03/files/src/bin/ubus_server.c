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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <libubus.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>
#include "ioctl_tool.h"
#include "netlink_tool.h"

#define MAC_ADDRESS_LENGTH	17

enum {
	UBUS_METHOD_ARGUMENT_1,
	UBUS_METHOD_ARGUMENT_2,
	UBUS_METHOD_ARGUMENT_3,
	UBUS_METHOD_ARGUMENT_4,
	UBUS_METHOD_ARGUMENT_5,
	UBUS_METHOD_ARGUMENT_6,
	UBUS_METHOD_ARGUMENT_7,
	UBUS_METHOD_ARGUMENT_MAX,
};

static struct blob_buf blob;

void blobmsg_error(struct blob_buf *blob, int result, const char *method) {

	// Common Error Message
	switch (result) {
		case ERR_SOCKET:
			blobmsg_add_string(blob, "Error", "Failed to create socket.");
			return;
		
		case ERR_INET_PTON:
			blobmsg_add_string(blob, "Error", "Failed to convert ip address.");
			return;

		case ERR_INET_PTON_DST:
			blobmsg_add_string(blob, "Error", "Failed to convert destination ip address.");
			return;
		
		case ERR_INET_PTON_GT:
			blobmsg_add_string(blob, "Error", "Failed to convert gateway ip address.");
			return;

		case ERR_INET_PTON_MASK:
			blobmsg_add_string(blob, "Error", "Failed to convert gateway ip address.");
			return;

		case ERR_MAC_FORMAT:
			blobmsg_add_string(blob, "Error", "Invalid MAC Address Format.");
			return;
	}

	// add_route Error Message
	if (strcmp(method, "add_route") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to add routing table (SIOCADDRT).");
				return;
		}
	}

	// delete_route Error Message
	if (strcmp(method, "delete_route") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to delete routing table (SIOCDELRT).");
				return;
		}
	}

	// handle_rtmsg Error Message
	if (strcmp(method, "handle_rtmsg") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve routing infomation (SIOCRTMSG).");
				return;
		}
	}

	// get_ifname_from_idx Error Message
	if (strcmp(method, "get_ifname_from_idx") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve interface name (SIOCGIFNAME).");
				return;
		}
	}
	
	// list_if method Error Message
	if (strcmp(method, "list_if") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve interface list (SIOCGIFCONF).");
				return;
		}
	}

	// get_if_flags Error Message
	if (strcmp(method, "get_if_flags") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve interface flag (SIOCGIFFLAGS).");
				return;
		}
	}

	// set_if_ipv4 Error Message
	if (strcmp(method, "set_if_ipv4") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCSIFADDR).");
				return;
		}
	}

	// get_if_ipv4 Error Message
	if (strcmp(method, "get_if_ipv4") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFADDR).");
				return;
		}
	}

	// get_dest_addr Error Message
	if (strcmp(method, "get_dest_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFDSTADDR).");
				return;
		}
	}

	// set_dest_addr Error Message
	if (strcmp(method, "set_dest_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCSIFDSTADDR).");
				return;
		}
	}

	// get_bcast_addr Error Message
	if (strcmp(method, "get_bcast_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFBRDADDR).");
				return;
		}
	}

	// set_bcast_addr Error Message
	if (strcmp(method, "set_bcast_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCSIFBRDADDR).");
				return;
		}
	}

	// get_netmask Error Message
	if (strcmp(method, "get_netmask") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFNETMASK).");
				return;
		}
	}

	// get_mtu Error Message
	if (strcmp(method, "get_mtu") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFMTU).");
				return;
		}
	}

	// set_mtu Error Message
	if (strcmp(method, "set_mtu") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCSIFMTU).");
				return;
		}
	}

	// get_mac_addr Error Message
	if (strcmp(method, "get_mac_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFHWADDR).");
				return;
		}
	}

	// delete_arp_entry Error Message
	if (strcmp(method, "delete_arp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target ip address is not found (SIOCDARP).");
				return;
		}
	}

	// set_arp_entry Error Message
	if (strcmp(method, "set_arp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target ip address is not found (SIOCSARP).");
				return;
		}
	}

	// get_arp_entry Error Message
	if (strcmp(method, "get_arp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target ip address is not found (SIOCGARP).");
				return;
		}
	}

	// get_rarp_entry Error Message
	if (strcmp(method, "get_rarp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target mac address is not found (SIOCGARP).");
				return;
		}
	}

	// get_if_map Error Message
	if (strcmp(method, "get_if_map") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFMAP).");
				return;
		}
	}

	// get_if_map Error Message
	if (strcmp(method, "get_tx_que_len") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFTXQLEN).");
				return;
		}
	}

	// set_if_flags Error Message
	if (strcmp(method, "set_if_flags") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCSIFFLAGS).");
				return;
		}
	}

	blobmsg_add_string(blob, "Error", "Unknown");
}

/* Ubus method policy */
// --- TYPE List ---
// BLOBMSG_TYPE_ARRAY
// BLOBMSG_TYPE_TABLE
// BLOBMSG_TYPE_STRING
// BLOBMSG_TYPE_INT64
// BLOBMSG_TYPE_INT32
// BLOBMSG_TYPE_INT8
// BLOBMSG_TYPE_BOOL
// BLOBMSG_TYPE_DOUBLE

static const struct blobmsg_policy add_route_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="destination", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="gateway", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="netmask", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_4] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy delete_route_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="destination", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="netmask", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy handle_rtmsg_method_policy[] = {};

static const struct blobmsg_policy get_ifname_from_idx_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="if index", .type=BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy set_if_link_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="link index", .type=BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy list_if_method_policy[] = {};

static const struct blobmsg_policy get_if_flags_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_if_ipv4_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="ip address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_if_ipv4_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_dest_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_dest_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="ipaddr", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_bcast_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_bcast_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="bcastaddr", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_netmask_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_netmask_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="netmask", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_mtu_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_mtu_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="mtu", .type=BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy get_mac_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_mac_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_1] = { .name="mac", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy delete_arp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ipaddr", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_arp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="ipaddr", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="macaddr", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_arp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="neighbor ip address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy delete_rarp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ip address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_rarp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ip address", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="neighbor mac address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_rarp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="neighbor mac address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_if_map_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_if_map_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="mem_start", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="mem_end", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_4] = { .name="base_addr", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_5] = { .name="irq", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_6] = { .name="dma", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_7] = { .name="port", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_tx_que_len_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy set_if_flags_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="flag to set", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="flag to clear", .type=BLOBMSG_TYPE_STRING },
};

// netlink
static const struct blobmsg_policy netlink_list_if_method_policy[] = {};

/* ubus methods */
static int add_route_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int delete_route_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int handle_rtmsg_method(struct ubus_context *, struct ubus_object *,
			  struct ubus_request_data *, const char *,
			  struct blob_attr *);

static int get_ifname_from_idx_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_if_link_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int list_if_method(struct ubus_context *, struct ubus_object *,
			  struct ubus_request_data *, const char *,
			  struct blob_attr *);

static int set_if_flags_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_if_flags_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_if_ipv4_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_if_ipv4_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_dest_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_dest_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_bcast_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_bcast_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_mtu_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_mtu_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_mac_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_arp_entry_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_rarp_entry_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_rarp_entry_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_if_map_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int set_if_map_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_tx_que_len_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

//netlink
static int netlink_list_if_method(struct ubus_context *, struct ubus_object *,
			  struct ubus_request_data *, const char *,
			  struct blob_attr *);

//Function equivalent to the uci get command.
bool uci_get_option(char* str, char* value);

//Function equivalent to the uci set command.
bool uci_set_option(char* str);

static void ubus_sample_handle_signal(int signo)
{
	uloop_end();
}

static void ubus_sample_setup_signals(void)
{
	struct sigaction s;

	memset(&s, 0, sizeof(s));
	s.sa_handler = ubus_sample_handle_signal;
	s.sa_flags = 0;
	sigaction(SIGTERM, &s, NULL);
}

/*************************/
/* Ubus method functions */
/*************************/
int add_route_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(add_route_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]
		|| !tb[UBUS_METHOD_ARGUMENT_3] || !tb[UBUS_METHOD_ARGUMENT_4]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *dest = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *gateway = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);
	const char *netmask = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_3]);
	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_4]);

	int result = add_route(dest, gateway, netmask, ifname);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "Success", "Add new routing table");
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

int delete_route_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(delete_route_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]
		|| !tb[UBUS_METHOD_ARGUMENT_3] || !tb[UBUS_METHOD_ARGUMENT_4]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *dest = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *netmask = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);
	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_3]);

	int result = delete_route(dest, netmask, ifname);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "Success", "Delete routing table");
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

int handle_rtmsg_method(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {
	
	char message[1024] = {'\0'};
	int result = handle_rtmsg(message, sizeof(message));

	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "routing infomation", message);
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

int get_ifname_from_idx_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_ifname_from_idx_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]) {
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char ifname[IFNAMSIZ];
	int if_idx = blobmsg_get_u32(tb[UBUS_METHOD_ARGUMENT_1]);

	int result = get_ifname_from_idx(if_idx, ifname, sizeof(ifname));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "ifname", ifname);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

int set_if_link_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_if_link_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]) {
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	int if_idx = blobmsg_get_u32(tb[UBUS_METHOD_ARGUMENT_2]);

	int result = set_if_link(ifname, if_idx);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char message[64];
		snprintf(message, sizeof(message), "Set the link number %d on %s.", if_idx, ifname);
		blobmsg_add_string(&blob, "Success", message);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool list_if '{}'
int list_if_method(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {
	
	const int max_if_num = 32;

	if_list list[max_if_num];
	memset(list, '\0', sizeof(list));

	int result = list_if(list, max_if_num);

	void *s;
	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {

		int i;

		for (i = 0; i < max_if_num; i++) {

			if (strlen(list[i].name) == 0) {
				break;
			}

			char if_item_name[64] = {'\0'};
			snprintf(if_item_name, sizeof(if_item_name), "if_item_%d", (i + 1));
			s = blobmsg_open_table(&blob, if_item_name);
			blobmsg_add_string(&blob, "interface", list[i].name);
			blobmsg_add_string(&blob, "ipv4 address", list[i].ipv4_addr);
			blobmsg_close_table(&blob, s);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_if_flags '{"ifname":"eth0"}'
static int get_if_flags_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_if_flags_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	flag_info info;

	int result = get_if_flags(ifname, &info);

	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		int i;
		void *s = blobmsg_open_table(&blob, "info");
		char msg_key_name[256];

		blobmsg_add_string(&blob, "flag", info.flag);

		for (i = 0; i < MAX_FLAG_NUM; i++) {
			if (strlen(info.message[i]) > 0) {
				snprintf(msg_key_name, sizeof(msg_key_name), "%s%d", "message_", (i + 1));
				blobmsg_add_string(&blob, msg_key_name, info.message[i]);
			}
		}

		blobmsg_close_table(&blob, s);
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_if_ipv4 '{"ifname":"eth0", "ip address":"192.168.1.1"}'
static int set_if_ipv4_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_if_ipv4_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *ipv4_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(ipv4_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "The ipv4 address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_if_ipv4(ifname, ipv4_addr);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char ipv4_addr[INET_ADDRSTRLEN];
		int result = get_if_ipv4(ifname, ipv4_addr, sizeof(ipv4_addr));
		if (result != 0) {
			blobmsg_error(&blob, result, "get_if_ipv4");
		} else {
			blobmsg_add_string(&blob, "Current ipv4 address", ipv4_addr);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_if_ipv4 '{"ifname":"eth0"}'
static int get_if_ipv4_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_if_ipv4_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char ipv4_addr[INET_ADDRSTRLEN];

	int result = get_if_ipv4(ifname, ipv4_addr, sizeof(ipv4_addr));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "ipv4 address", ipv4_addr);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_dest_addr '{"ifname":"eth0"}'
static int get_dest_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_dest_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char dest_ipv4_addr[INET_ADDRSTRLEN];
	int result = get_dest_addr(ifname, dest_ipv4_addr, sizeof(dest_ipv4_addr));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "Destination ipv4 address", dest_ipv4_addr);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_dest_addr '{"ifname":"eth0", "ipaddr":"192.168.2.1"}'
static int set_dest_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_dest_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *dest_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(dest_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target ip address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_dest_addr(ifname, dest_addr);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char dest_ipv4_addr[INET_ADDRSTRLEN];
		int result = get_dest_addr(ifname, dest_ipv4_addr, sizeof(dest_ipv4_addr));

		if (result != 0) {
			blobmsg_error(&blob, result, "get_dest_addr");
		} else {
			blobmsg_add_string(&blob, "Destination ipv4 address", dest_ipv4_addr);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_bcast_addr '{"ifname":"eth0"}'
static int get_bcast_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_bcast_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char bcast_ipv4_addr[INET_ADDRSTRLEN];

	int result = get_bcast_addr(ifname, bcast_ipv4_addr, sizeof(bcast_ipv4_addr));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "Broadcast ipv4 address", bcast_ipv4_addr);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_bcast_addr '{"ifname":"eth0", "bcastaddr":"255.255.255.0"}'
static int set_bcast_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_bcast_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *bcast_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(bcast_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "The broadcast address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_bcast_addr(ifname, bcast_addr);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char bcast_ipv4_addr[INET_ADDRSTRLEN];

		int result = get_bcast_addr(ifname, bcast_ipv4_addr, sizeof(bcast_ipv4_addr));

		if (result != 0) {
			blobmsg_error(&blob, result, "get_bcast_addr");
		} else {
			blobmsg_add_string(&blob, "Broadcast ipv4 address", bcast_ipv4_addr);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_netmask '{"ifname":"eth0"}'
static int get_netmask_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_netmask_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char netmask[INET_ADDRSTRLEN];
	int result = get_netmask(ifname, netmask, sizeof(netmask));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "Subnet Mask", netmask);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_netmask '{"ifname":"eth0", "netmask":"255.255.255.0"}'
static int set_netmask_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_netmask_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *netmask = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(netmask) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target subnet mask is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_netmask(ifname, netmask);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char netmask[INET_ADDRSTRLEN];
		int result = get_netmask(ifname, netmask, sizeof(netmask));

		if (result != 0) {
			blobmsg_error(&blob, result, "get_netmask");
		} else {
			blobmsg_add_string(&blob, "Subnet Mask", netmask);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_mtu '{"ifname":"eth0"}'
static int get_mtu_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_mtu_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int mtu;
	int result = get_mtu(ifname, &mtu);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_u32(&blob, "mtu", mtu);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_mtu '{"ifname":"eth0", "mtu":1500}'
static int set_mtu_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_mtu_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const int mtu = blobmsg_get_u32(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_mtu(ifname, mtu);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		int mtu;
		int result = get_mtu(ifname, &mtu);
		if (result != 0) {
			blobmsg_error(&blob, result, "get_mtu");
		} else {
			blobmsg_add_u32(&blob, "mtu", mtu);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_mac_addr '{"ifname":"eth0"}'
static int get_mac_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_mac_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	char mac_addr[64];
	int result = get_mac_addr(ifname, mac_addr, sizeof(mac_addr));

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "MAC address", mac_addr);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_mac_addr '{"ifname":"eth0", "mac":"AA:BB:CC:EE:DD:FF"}'
static int set_mac_addr_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {
	
	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_mac_addr_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *mac = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(mac) > MAC_ADDRESS_LENGTH) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_mac_addr(ifname, mac);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char mac_addr[64];
		int result = get_mac_addr(ifname, mac_addr, sizeof(mac_addr));

		if (result != 0) {
			blobmsg_error(&blob, result, method);
		} else {
			blobmsg_add_string(&blob, "MAC address", mac_addr);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool delete_arp_entry '{"ipaddr":"192.168.1.1"}'
static int delete_arp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(delete_arp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ip_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ip_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target ip address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = delete_arp_entry(ip_addr);
	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char message[256];
		snprintf(message, sizeof(message), "Delete the ARP entry for %s", ip_addr);
		blobmsg_add_string(&blob, "Success", message);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool set_arp_entry '{"ifname":"eth0", "macaddr":"AA:BB:CC:DD:EE:FF", "ipaddr":"192.168.1.1"}'
static int set_arp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_arp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2] || !tb[UBUS_METHOD_ARGUMENT_3]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *ip_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);
	const char *mac_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_3]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(ip_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target ip address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(mac_addr) > MAC_ADDRESS_LENGTH) {
		blobmsg_add_string(&blob, "Error", "Target mac address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = set_arp_entry(ifname, ip_addr, mac_addr);
	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		arp_entry_info info;
		int result = get_arp_entry(ip_addr, &info);

		if (result != 0) {
			blobmsg_error(&blob, result, "get_arp_entry");
		} else {
			blobmsg_add_string(&blob, "MAC address", info.mac_addr);
			blobmsg_add_string(&blob, "FLAG", info.flag);
			void *s = blobmsg_open_table(&blob, "info");
			int i;
			for (i = 0; i < MAX_FLAG_NUM; i++) {
				char msg_key_name[256];
				snprintf(msg_key_name, sizeof(msg_key_name), "message_%d", (i + 1));
				if (strlen(info.message[i]) > 0) {
					blobmsg_add_string(&blob, msg_key_name, info.message[i]);
				}
			}
			blobmsg_close_table(&blob, s);
		}
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_arp_entry '{"ip address":"192.168.1.1"}'
static int get_arp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_arp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ip_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ip_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target ip address is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	arp_entry_info info;
	int result = get_arp_entry(ip_addr, &info);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "MAC address", info.mac_addr);
		blobmsg_add_string(&blob, "FLAG", info.flag);
		void *s = blobmsg_open_table(&blob, "info");
		int i;
		for (i = 0; i < MAX_FLAG_NUM; i++) {
			char msg_key_name[256];
			snprintf(msg_key_name, sizeof(msg_key_name), "message_%d", (i + 1));
			if (strlen(info.message[i]) > 0) {
				blobmsg_add_string(&blob, msg_key_name, info.message[i]);
			}
		}
		blobmsg_close_table(&blob, s);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool delete_rarp_entry '{"ip address":""192.168.1.2}'
static int delete_rarp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(delete_rarp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ip_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ip_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int result = delete_rarp_entry(ip_addr);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		char message[256];
		snprintf(message, sizeof(message), "Delete the RARP entry for %s", ip_addr);
		blobmsg_add_string(&blob, "Success", message);
	}

	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_rarp_entry '{"neighbor ip address":"192.168.1.1"}'
static int set_rarp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_rarp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ip_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *mac_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);

	blob_buf_init(&blob, 0);

	if (strlen(ip_addr) > INET_ADDRSTRLEN) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	if (strlen(mac_addr) > MAC_ADDRESS_LENGTH) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	rarp_entry_info info;
	int result = get_rarp_entry(mac_addr, &info);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "ip address", info.ip_addr);
		blobmsg_add_string(&blob, "FLAG", info.flag);
		void *s = blobmsg_open_table(&blob, "info");
		int i;
		for (i = 0; i < MAX_FLAG_NUM; i++) {
			char msg_key_name[256];
			snprintf(msg_key_name, sizeof(msg_key_name), "message_%d", (i + 1));
			if (strlen(info.message[i]) > 0) {
				blobmsg_add_string(&blob, msg_key_name, info.message[i]);
			}
		}
		blobmsg_close_table(&blob, s);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usasge:
// root@OpenWrt:~# ubus call ioctl-tool get_rarp_entry '{"neighbor ip address":"192.168.1.1"}'
static int get_rarp_entry_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_rarp_entry_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *mac_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(mac_addr) > MAC_ADDRESS_LENGTH) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	rarp_entry_info info;
	int result = get_rarp_entry(mac_addr, &info);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "ip address", info.ip_addr);
		blobmsg_add_string(&blob, "FLAG", info.flag);
		void *s = blobmsg_open_table(&blob, "info");
		int i;
		for (i = 0; i < MAX_FLAG_NUM; i++) {
			char msg_key_name[256];
			snprintf(msg_key_name, sizeof(msg_key_name), "message_%d", (i + 1));
			if (strlen(info.message[i]) > 0) {
				blobmsg_add_string(&blob, msg_key_name, info.message[i]);
			}
		}
		blobmsg_close_table(&blob, s);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_if_map '{"ifname":"eth0"}'
static int get_if_map_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_if_map_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	map_info info;
	int result = get_if_map(ifname, &info);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "mem_start", info.mem_start);
		blobmsg_add_string(&blob, "mem_end", info.mem_end);
		blobmsg_add_string(&blob, "base_addr", info.base_addr);
		blobmsg_add_u32(&blob, "irq", info.irq);
		blobmsg_add_u32(&blob, "dma", info.dma);
		blobmsg_add_u32(&blob, "port", info.port);
	}

	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

static int set_if_map_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_if_map_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2] || !tb[UBUS_METHOD_ARGUMENT_3] 
		|| !tb[UBUS_METHOD_ARGUMENT_4] || !tb[UBUS_METHOD_ARGUMENT_5] || !tb[UBUS_METHOD_ARGUMENT_6]
		|| !tb[UBUS_METHOD_ARGUMENT_7]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *mem_start = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);
	const char *mem_end = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_3]);
	const char *base_addr = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_4]);
	const char *irq = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_5]);
	const char *dma = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_6]);
	const char *port = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_7]);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	struct ifmap map;
	map.mem_start = (unsigned long)strtol(mem_start, NULL, 16);
	map.mem_end = (unsigned long)strtol(mem_end, NULL, 16);
	map.base_addr = (unsigned short)strtol(base_addr, NULL, 16);
	map.irq = (unsigned char)strtol(irq, NULL, 16);
	map.dma = (unsigned char)strtol(dma, NULL, 16);
	map.port = (unsigned char)strtol(port, NULL, 16);

	blob_buf_init(&blob, 0);

	int result = set_if_map(ifname, map);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		map_info info;
		int result = get_if_map(ifname, &info);

		if (result != 0) {
			blobmsg_error(&blob, result, "get_if_map");
		} else {
			blobmsg_add_string(&blob, "mem_start", info.mem_start);
			blobmsg_add_string(&blob, "mem_end", info.mem_end);
			blobmsg_add_string(&blob, "base_addr", info.base_addr);
			blobmsg_add_u32(&blob, "irq", info.irq);
			blobmsg_add_u32(&blob, "dma", info.dma);
			blobmsg_add_u32(&blob, "port", info.port);
		}
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

// usage:
// root@OpenWrt:~# ubus call ioctl-tool get_tx_que_len '{"ifname":"eth0"}'
static int get_tx_que_len_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(get_tx_que_len_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	int qlen;
	int result = get_tx_que_len(ifname, &qlen);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_u32(&blob, "tx_que_len", qlen);
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

static int set_if_flags_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	struct blob_attr *tb[UBUS_METHOD_ARGUMENT_MAX];
	blobmsg_parse(set_if_flags_method_policy, UBUS_METHOD_ARGUMENT_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UBUS_METHOD_ARGUMENT_1] || !tb[UBUS_METHOD_ARGUMENT_2] || !tb[UBUS_METHOD_ARGUMENT_3]){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Error", "Mismatch Key");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

	const char *ifname = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_1]);
	const char *str_flags_to_set = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_2]);
	const char *str_flags_to_clear = blobmsg_get_string(tb[UBUS_METHOD_ARGUMENT_3]);

	blob_buf_init(&blob, 0);

	if (strlen(ifname) > IFNAMSIZ) {
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
		ubus_send_reply(ctx, req, blob.head);
		return -1;
	}

    short short_flags_to_set = (short)strtol(str_flags_to_set, NULL, 16);
    short short_flags_to_clear = (short)strtol(str_flags_to_clear, NULL, 16);

	int result = set_if_flags(ifname, short_flags_to_set, short_flags_to_clear);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		flag_info info;
		int result = get_if_flags(ifname, &info);
		if (result != 0) {
			blobmsg_error(&blob, result, "get_if_flags");
		} else {
			int i;
			void *s = blobmsg_open_table(&blob, "info");
			char msg_key_name[256];

			blobmsg_add_string(&blob, "flag", info.flag);

			for (i = 0; i < MAX_FLAG_NUM; i++) {
				if (strlen(info.message[i]) > 0) {
					snprintf(msg_key_name, sizeof(msg_key_name), "%s%d", "message_", (i + 1));
					blobmsg_add_string(&blob, msg_key_name, info.message[i]);
				}
			}

			blobmsg_close_table(&blob, s);
		}
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

static int netlink_list_if_method(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg) {

	const int max_if_num = 32;
	netlink_if_list list[max_if_num];
	memset(list, '\0', sizeof(list));

	int result = netlink_list_if(list, max_if_num);

	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		void *s;
		int i;
		for (i = 0; i < max_if_num; i++) {

			if (strlen(list[i].ifname) == 0) {
				break;
			}

			char if_item_name[64] = {'\0'};
			snprintf(if_item_name, sizeof(if_item_name), "if_item_%d", (i + 1));
			s = blobmsg_open_table(&blob, if_item_name);
			blobmsg_add_u32(&blob, "index", list[i].index);
			blobmsg_add_string(&blob, "ifname", list[i].ifname);
			blobmsg_close_table(&blob, s);
		}
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

/* Ubus object methods */
const struct ubus_method ubus_sample_netlink_methods[] = {
	UBUS_METHOD("list_if", netlink_list_if_method, netlink_list_if_method_policy),
};

const struct ubus_method ubus_sample_ioctl_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
#ifdef SUPPORT_ADD_ROUTE
	UBUS_METHOD("add_route", add_route_method, add_route_method_policy),
#endif

#ifdef SUPPORT_DELETE_ROUTE
	UBUS_METHOD("delete_route", delete_route_method, delete_route_method_policy),
#endif

#ifdef SUPPORT_HANDLE_RTMSG
	UBUS_METHOD("handle_rtmsg", handle_rtmsg_method, handle_rtmsg_method_policy),
#endif

#ifdef SUPPORT_GET_IFNAME_FROM_IDX
	UBUS_METHOD("get_ifname_from_idx", get_ifname_from_idx_method, get_ifname_from_idx_method_policy),
#endif

#ifdef SUPPORT_SET_IF_LINK
	UBUS_METHOD("set_if_link", set_if_link_method, set_if_link_method_policy),
#endif

#ifdef SUPPORT_LIST_IF
	UBUS_METHOD("list_if", list_if_method, list_if_method_policy),
#endif

#ifdef SUPPORT_SET_IF_FLAGS
	UBUS_METHOD("set_if_flags", set_if_flags_method, set_if_flags_method_policy),
#endif

#ifdef SUPPORT_GET_IF_FLAGS
	UBUS_METHOD("get_if_flags", get_if_flags_method, get_if_flags_method_policy),
#endif

#ifdef SUPPORT_SET_IF_IPV4
	UBUS_METHOD("set_if_ipv4", set_if_ipv4_method, set_if_ipv4_method_policy),
#endif

#ifdef SUPPORT_GET_IF_IPV4
	UBUS_METHOD("get_if_ipv4", get_if_ipv4_method, get_if_ipv4_method_policy),
#endif

#ifdef SUPPORT_GET_DEST_ADDR
	UBUS_METHOD("get_dest_addr", get_dest_addr_method, get_dest_addr_method_policy),
#endif

#ifdef SUPPORT_SET_DEST_ADDR
	UBUS_METHOD("set_dest_addr", set_dest_addr_method, set_dest_addr_method_policy),
#endif

#ifdef SUPPORT_GET_BCAST_ADDR
	UBUS_METHOD("get_bcast_addr", get_bcast_addr_method, get_bcast_addr_method_policy),
#endif

#ifdef SUPPORT_SET_BCAST_ADDR
	UBUS_METHOD("set_bcast_addr", set_bcast_addr_method, set_bcast_addr_method_policy),
#endif

#ifdef SUPPORT_GET_NETMASK
	UBUS_METHOD("get_netmask", get_netmask_method, get_netmask_method_policy),
#endif

#ifdef SUPPORT_SET_NETMASK
	UBUS_METHOD("set_netmask", set_netmask_method, set_netmask_method_policy),
#endif

#ifdef SUPPORT_GET_MTU
	UBUS_METHOD("get_mtu", get_mtu_method, get_mtu_method_policy),
#endif

#ifdef SUPPORT_GET_MTU
	UBUS_METHOD("set_mtu", set_mtu_method, set_mtu_method_policy),
#endif

#ifdef SUPPORT_GET_MAC_ADDR
	UBUS_METHOD("get_mac_addr", get_mac_addr_method, get_mac_addr_method_policy),
#endif

#ifdef SUPPORT_SET_MAC_ADDR
	UBUS_METHOD("set_mac_addr", set_mac_addr_method, set_mac_addr_method_policy),
#endif

#ifdef SUPPORT_DELETE_ARP_ENTRY
	UBUS_METHOD("delete_arp_entry", delete_arp_entry_method, delete_arp_entry_method_policy),
#endif

#ifdef SUPPORT_SET_ARP_ENTRY
	UBUS_METHOD("set_arp_entry", set_arp_entry_method, set_arp_entry_method_policy),
#endif

#ifdef SUPPORT_GET_ARP_ENTRY
	UBUS_METHOD("get_arp_entry", get_arp_entry_method, get_arp_entry_method_policy),
#endif

#ifdef SUPPORT_DELETE_RARP_ENTRY
	UBUS_METHOD("delete_rarp_entry", delete_rarp_entry_method, delete_rarp_entry_method_policy),
#endif

#ifdef SUPPORT_SET_RARP_ENTRY
	UBUS_METHOD("set_rarp_entry", set_rarp_entry_method, set_rarp_entry_method_policy),
#endif

#ifdef SUPPORT_GET_RARP_ENTRY
	UBUS_METHOD("get_rarp_entry", get_rarp_entry_method, get_rarp_entry_method_policy),
#endif

#ifdef SUPPORT_GET_IF_MAP
	UBUS_METHOD("get_if_map", get_if_map_method, get_if_map_method_policy),
#endif

#ifdef SUPPORT_SET_IF_MAP
	UBUS_METHOD("set_if_map", set_if_map_method, set_if_map_method_policy),
#endif

#ifdef SUPPORT_GET_TX_QUE_LEN
	UBUS_METHOD("get_tx_que_len", get_tx_que_len_method, get_tx_que_len_method_policy),
#endif
};

/* Ubus object type */
struct ubus_object_type ubus_sample_ioctl_obj_type = UBUS_OBJECT_TYPE("luci-app-sample03-ioctl-uobj", ubus_sample_ioctl_methods);
struct ubus_object_type ubus_sample_netlink_obj_type = UBUS_OBJECT_TYPE("luci-app-sample03-netlink-uobj", ubus_sample_netlink_methods);


int main(int argc, char** argv)
{
	ubus_sample_setup_signals();

	/* Ubus object */
	struct ubus_object ubus_ioctl_object=
	{
		.name = "ioctl-tool", //objpath
		.type = &ubus_sample_ioctl_obj_type,
		.methods = ubus_sample_ioctl_methods,
		.n_methods = ARRAY_SIZE(ubus_sample_ioctl_methods),
	};

	struct ubus_object ubus_netlink_object=
	{
		.name = "netlink-tool", //objpath
		.type = &ubus_sample_netlink_obj_type,
		.methods = ubus_sample_netlink_methods,
		.n_methods = ARRAY_SIZE(ubus_sample_netlink_methods),
	};

	uloop_init();
	struct ubus_context *ctx = ubus_connect(NULL);
	ubus_add_uloop(ctx);
	ubus_add_object(ctx, &ubus_ioctl_object);
	ubus_add_object(ctx, &ubus_netlink_object);
	uloop_run();
	uloop_done();

	return EXIT_SUCCESS;
}
