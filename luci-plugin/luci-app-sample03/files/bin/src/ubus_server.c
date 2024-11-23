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
	UCI_SET_INFO_OPTION,
	UCI_SET_INFO_VALUE,
	UCI_SET_INFO_MAX,
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
}

/* Ubus method policy */
static const struct blobmsg_policy list_if_method_policy[] = {};

/* ubus methods */
static int list_if_method(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

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

// Ubus method functions
//output the uci configuration file.
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

/* Ubus object methods */
const struct ubus_method ubus_sample_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
#ifdef SUPPORT_LIST_IF
	UBUS_METHOD("list_if", list_if_method, list_if_method_policy),
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
