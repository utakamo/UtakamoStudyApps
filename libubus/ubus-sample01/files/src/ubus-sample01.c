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
#include <uci.h>

enum {
	UCI_SET_INFO_OPTION,
	UCI_SET_INFO_VALUE,
	UCI_SET_INFO_MAX,
};

static struct blob_buf blob;

/* user input json data */
struct uci_set_data {
	struct avl_node avl;
	char *option;
	char *value;
};

struct avl_tree uci_set_datas;

const char* find_uci_option(const char *user_input)
{
	struct uci_set_data *o;
	o = avl_find_element(&uci_set_datas, user_input, o, avl);
	if (!o)
		return NULL;
	return o;
}

/* Ubus method policy */
static const struct blobmsg_policy check_json_format_policy[] = {};
static const struct blobmsg_policy show_uci_option_policy[] = {};
static const struct blobmsg_policy update_uci_option_policy[] =
{
	[UCI_SET_INFO_OPTION] = { .name="option", .type=BLOBMSG_TYPE_STRING },
	[UCI_SET_INFO_VALUE] = { .name="value", .type=BLOBMSG_TYPE_STRING },
};


/* ubus methods */
static int check_json_format(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

static int show_uci_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

static int update_uci_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);


void ubus_process(void);

//Function equivalent to the uci get command.
bool uci_get_option(char* str, char* value);

//Function equivalent to the uci set command.
bool uci_set_option(char* str);

/* GLOBAL VARIABLE DECLARATION */
bool terminate_flg = false;
bool reload_flg = false;

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
//Execution is triggered at startup and [/etc/init.d/ubus-sample01].
int check_json_format(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {
	void *s;
	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "Description", "[ubus json format]");
	blobmsg_add_string(&blob, "string", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	blobmsg_add_u8(&blob, "bool", true);
	blobmsg_add_u32(&blob, "numeric data", 100);
	s = blobmsg_open_table(&blob, "table");
	blobmsg_add_string(&blob, "table-element1", "string data");
	blobmsg_add_u8(&blob, "table-element2", true);
	blobmsg_add_u32(&blob, "table-element3", 200);
	blobmsg_close_table(&blob, s);
	blobmsg_add_string(&blob, "Note", "Please read this source code for detailed usage.");
	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

int show_uci_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {

	char data1[256] = {0};
	char data2[256] = {0};
	char data3[256] = {0};

	bool is_option = false;
	//uci get ubus-sample01.test.user
	uci_get_option("ubus-sample01.test.data1", data1);
	uci_get_option("ubus-sample01.test.data2", data2);
	uci_get_option("ubus-sample01.test.data3", data3);

	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "Description", "Output /etc/config/ubus-sample01");
	blobmsg_add_string(&blob, "data1", data1);
	blobmsg_add_string(&blob, "data2", data2);
	blobmsg_add_string(&blob, "data3", data3);
	ubus_send_reply(ctx, req, blob.head);

	return 0;
}


int update_uci_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {

	struct blob_attr *tb[UCI_SET_INFO_MAX];

	blobmsg_parse(update_uci_option_policy, UCI_SET_INFO_MAX, tb, blob_data(msg), blob_len(msg));

	if ((!tb[UCI_SET_INFO_OPTION]) || (!tb[UCI_SET_INFO_VALUE])){
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Result", "[UCI SET FAILED] NO INPUT JSON DATA!!");
		ubus_send_reply(ctx, req, blob.head);

		return -1;
	}

	const char *option = blobmsg_get_string(tb[UCI_SET_INFO_OPTION]);
	const char *value = blobmsg_get_string(tb[UCI_SET_INFO_VALUE]);

	if (!option || !value) {
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Result", "[UCI SET FAILED] NOT FOUND UCI OPTION!!");
		ubus_send_reply(ctx, req, blob.head);

		return -1;
	}

	char update_data[1024];
	snprintf(update_data, sizeof(update_data), "ubus-sample01.test.%s=%s", option, value);

	bool result = uci_set_option(update_data);

	if (!result) {
		blob_buf_init(&blob, 0);
		blobmsg_add_string(&blob, "Result", "[UCI SET FAILED] UCI ERROR!!");
		ubus_send_reply(ctx, req, blob.head);

		return -1;
	}

	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "Result", "[UCI SET SUCCESS] Please check ubus-sample01 config!!");
	blobmsg_add_string(&blob, "Note", "ex) user~# uci show ubus-sample01");
	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

/* Ubus object methods */
const struct ubus_method ubus_sample_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
	UBUS_METHOD("check_json_format", check_json_format, check_json_format_policy),
	UBUS_METHOD("show_uci_option", show_uci_option, show_uci_option_policy),
	UBUS_METHOD("update_uci_option", update_uci_option, update_uci_option_policy),
};

/* Ubus object type */
struct ubus_object_type ubus_sample_obj_type = UBUS_OBJECT_TYPE("ubus-sample01-uobj", ubus_sample_methods);

/* Ubus object */
struct ubus_object ubus_sample_object=
{
	.name = "sample01", //objpath
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

//Function equivalent to the uci get command.
bool uci_get_option(char* str, char* value){
	struct uci_context *ctx;
	struct uci_ptr ptr;

	char* param = strdup(str);

	ctx = uci_alloc_context();

	if (param == NULL) {
		return false;
	}

	if (ctx == NULL) {
		return false;
	}

	if (uci_lookup_ptr(ctx, &ptr, param, true) != UCI_OK) {
		uci_perror(ctx, "uci set error");
		uci_free_context(ctx);
		return false;
	}

	if (ptr.o != 0 && ptr.o->type == UCI_TYPE_STRING) {
		if (sizeof(value) <= sizeof(ptr.o->v.string)) {
			strcpy(value, ptr.o->v.string);
		}
	}

	uci_free_context(ctx);
	free(param);
	return true;
}

//Function equivalent to the uci set command.
bool uci_set_option(char* str) {
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;

	ctx = uci_alloc_context();

	char* param = strdup(str);

	if (uci_lookup_ptr(ctx, &ptr, param, true) != UCI_OK) {
		uci_perror(ctx, "uci set error");
		uci_free_context(ctx);
		return false;
	}

	if (ptr.value)
		ret = uci_set(ctx, &ptr);
	else {
		ret = UCI_ERR_PARSE;
		uci_free_context(ctx);
		return false;
	}

	if (ret == UCI_OK) {
		uci_save(ctx, ptr.p);
		uci_commit(ctx, &ptr.p, true);
	}

	uci_free_context(ctx);
	return true;
}
