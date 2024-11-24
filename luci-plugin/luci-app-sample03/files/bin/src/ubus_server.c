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

enum {
	UBUS_METHOD_ARGUMENT_1,
	UBUS_METHOD_ARGUMENT_2,
	UBUS_METHOD_ARGUMENT_3,
	UBUS_METHOD_ARGUMENT_4,
	UBUS_METHOD_ARGUMENT_5,
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

		case ERR_MAC_FORMAT:
			blobmsg_add_string(blob, "Error", "Invalid MAC Address Format.");
			return;
	}

	// handle_rtmsg Error Message
	if (strcmp(method, "handle_rtmsg") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve routing infomation (SIOCRTMSG).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}
	
	// list_if method Error Message
	if (strcmp(method, "list_if") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve interface list (SIOCGIFCONF).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_if_flags Error Message
	if (strcmp(method, "get_if_flags") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Failed to retrieve interface flag (SIOCGIFFLAGS).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_if_ip Error Message
	if (strcmp(method, "get_if_ipv4") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFADDR).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_dest_addr Error Message
	if (strcmp(method, "get_dest_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFDSTADDR).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_bcast_addr Error Message
	if (strcmp(method, "get_bcast_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFBRDADDR).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_mtu Error Message
	if (strcmp(method, "get_mtu") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFMTU).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_mac_addr Error Message
	if (strcmp(method, "get_mac_addr") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFHWADDR).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_arp_entry Error Message
	if (strcmp(method, "get_arp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target ip address is not found (SIOCGARP).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_rarp_entry Error Message
	if (strcmp(method, "get_rarp_entry") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target mac address is not found (SIOCGARP).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_if_map Error Message
	if (strcmp(method, "get_if_map") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFMAP).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}

	// get_if_map Error Message
	if (strcmp(method, "get_tx_que_len") == 0) {
		switch (result) {
			case ERR_IOCTL:
				blobmsg_add_string(blob, "Error", "Target interface is not found (SIOCGIFTXQLEN).");
				return;

			default:
				blobmsg_add_string(blob, "Error", "Unknown");
				return;
		}
	}
}

/* Ubus method policy */
static const struct blobmsg_policy add_route_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="destination", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_2] = { .name="gateway", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_3] = { .name="netmask", .type=BLOBMSG_TYPE_STRING },
	[UBUS_METHOD_ARGUMENT_4] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy handle_rtmsg_method_policy[] = {};
static const struct blobmsg_policy list_if_method_policy[] = {};

static const struct blobmsg_policy get_if_flags_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_if_ipv4_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_dest_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_bcast_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_mtu_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_mac_addr_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_arp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="neighbor ip address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_rarp_entry_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="neighbor mac address", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_if_map_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy get_tx_que_len_method_policy[] = {
	[UBUS_METHOD_ARGUMENT_1] = { .name="ifname", .type=BLOBMSG_TYPE_STRING },
};

/* ubus methods */
static int add_route_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int handle_rtmsg_method(struct ubus_context *, struct ubus_object *,
			  struct ubus_request_data *, const char *,
			  struct blob_attr *);

static int list_if_method(struct ubus_context *, struct ubus_object *,
			  struct ubus_request_data *, const char *,
			  struct blob_attr *);

static int get_if_flags_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_if_ipv4_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_dest_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_mtu_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_mac_addr_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_arp_entry_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_rarp_entry_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_if_map_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);

static int get_tx_que_len_method(struct ubus_context *, struct ubus_object *,
                        struct ubus_request_data *, const char *,
                        struct blob_attr *);


void ubus_process(void);

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

int main(int argc, char** argv)
{
	ubus_sample_setup_signals();
	ubus_process();

	return EXIT_SUCCESS;
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

int handle_rtmsg_method(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {
	
	char message[1024] = {'\0'};
	int result = handle_rtmsg(message, sizeof(message));

	blob_buf_init(&blob, 0);

	if (result != 0) {
		blobmsg_error(&blob, result, method);
	} else {
		blobmsg_add_string(&blob, "routing infomation", "hello");
	}

	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

// usage:
// root@OpenWrt:~# ubus call luci-app-sample03 list_if '{}'
int list_if_method(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {
	
	const int max_if_num = 32;

	if_list list[max_if_num];

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

			char if_item_name[32] = {'\0'};
			snprintf(if_item_name, sizeof(if_item_name), "%s%d", "if_item_", (i + 1));
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_if_flags '{"ifname":"eth0"}'
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_if_ipv4 '{"ifname":"eth0"}'
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_dest_addr '{"ifname":"eth0"}'
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_bcast_addr '{"ifname":"eth0"}'
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_mtu '{"ifname":"eth0"}'
static int get_mtu_method(struct ubus_context *ctx, struct ubus_object *obj,
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_mac_addr '{"ifname":"eth0"}'
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_arp_entry '{"ip address":"192.168.1.1"}'
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
		blobmsg_add_string(&blob, "Error", "Target interface name is too long.");
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

// usasge:
// root@OpenWrt:~# ubus call luci-app-sample03 get_rarp_entry '{"neighbor ip address":"192.168.1.1"}'
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

	if (strlen(mac_addr) > 17) {
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
// root@OpenWrt:~# ubus call luci-app-sample03 get_if_map '{"ifname":"eth0"}'
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

// usage:
// root@OpenWrt:~# ubus call luci-app-sample03 get_tx_que_len '{"ifname":"eth0"}'
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

/* Ubus object methods */
const struct ubus_method ubus_sample_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
#ifdef SUPPORT_ADD_ROUTE
	UBUS_METHOD("add_route", add_route_method, add_route_method_policy),
#endif

#ifdef SUPPORT_HANDLE_RTMSG
	UBUS_METHOD("handle_rtmsg", handle_rtmsg_method, handle_rtmsg_method_policy),
#endif

#ifdef SUPPORT_LIST_IF
	UBUS_METHOD("list_if", list_if_method, list_if_method_policy),
#endif

#ifdef SUPPORT_GET_IF_FLAGS
	UBUS_METHOD("get_if_flags", get_if_flags_method, get_if_flags_method_policy),
#endif

#ifdef SUPPORT_GET_IF_IPV4
	UBUS_METHOD("get_if_ipv4", get_if_ipv4_method, get_if_ipv4_method_policy),
#endif

#ifdef SUPPORT_GET_DEST_ADDR
	UBUS_METHOD("get_dest_addr", get_dest_addr_method, get_dest_addr_method_policy),
#endif

#ifdef SUPPORT_GET_BCAST_ADDR
	UBUS_METHOD("get_bcast_addr", get_bcast_addr_method, get_bcast_addr_method_policy),
#endif

#ifdef SUPPORT_GET_MTU
	UBUS_METHOD("get_mtu", get_mtu_method, get_mtu_method_policy),
#endif

#ifdef SUPPORT_GET_MAC_ADDR
	UBUS_METHOD("get_mac_addr", get_mac_addr_method, get_mac_addr_method_policy),
#endif

#ifdef SUPPORT_GET_ARP_ENTRY
	UBUS_METHOD("get_arp_entry", get_arp_entry_method, get_arp_entry_method_policy),
#endif

#ifdef SUPPORT_GET_RARP_ENTRY
	UBUS_METHOD("get_rarp_entry", get_rarp_entry_method, get_rarp_entry_method_policy),
#endif

#ifdef SUPPORT_GET_IF_MAP
	UBUS_METHOD("get_if_map", get_if_map_method, get_if_map_method_policy),
#endif

#ifdef SUPPORT_GET_TX_QUE_LEN
	UBUS_METHOD("get_tx_que_len", get_tx_que_len_method, get_tx_que_len_method_policy),
#endif
};

/* Ubus object type */
struct ubus_object_type ubus_sample_obj_type = UBUS_OBJECT_TYPE("luci-app-sample03-uobj", ubus_sample_methods);

/* Ubus object */
struct ubus_object ubus_sample_object=
{
	.name = "luci-app-sample03", //objpath
	.type = &ubus_sample_obj_type,
	.methods = ubus_sample_methods,
	.n_methods = ARRAY_SIZE(ubus_sample_methods),
};

void ubus_process(void) {
	uloop_init();
	struct ubus_context *ctx = ubus_connect(NULL);
	ubus_add_uloop(ctx);
	ubus_add_object(ctx, &ubus_sample_object);
	uloop_run();
	uloop_done();
	return;
}
