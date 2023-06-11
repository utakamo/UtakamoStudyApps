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

#define FAILED_STRDUP			1
#define FAILED_ALLOC_UCI_CONTEXT	2
#define FAILED_EXTRACT_UCI_PARAMETER	3
#define HIT_UCI_OPTION			4
#define UCI_SEARCH_NOT_FOUND		5

static struct blob_buf blob;

/* Ubus method policy */
static const struct blobmsg_policy change_option_policy[] =
{
	{ .name="option", .type=BLOBMSG_TYPE_STRING },
	{ .name="value", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy output_option_policy[] = {};

/* ubus methods */
static int change_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

static int output_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

void ubus_process(void);

int uci_search_option(const char* str);

//Function equivalent to the uci get command.
bool uci_get_option(char* str, char* value);

//Function equivalent to the uci set command.
bool uci_set_option(char* str);

//Function equivalent to the uci commit command.
bool uci_commit_one_package(char* str);

/* GLOBAL VARIABLE DECLARATION */
bool terminate_flg = false;
bool reload_flg = false;

static void create_daemon()
{
	pid_t pid;

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);

	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);

	chdir("/");

	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close(x);
	}
}

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
	create_daemon();
	ubus_sample_setup_signals();
	ubus_process();

	return EXIT_SUCCESS;
}

// Ubus method functions
//output the uci configuration file.
//Execution is triggered at startup and [/etc/init.d/ubus-sample].
int change_option(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg) {

	void *s;
	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "reply", "Hmm? Did you call me?");
	blobmsg_add_string(&blob, "description", "Output sample data as follows");
	blobmsg_add_string(&blob, "string", "Welcome to ubus world!");
	blobmsg_add_u8(&blob, "bool1", true);
	blobmsg_add_u8(&blob, "bool2", false);
	blobmsg_add_u32(&blob, "numeric data", 100);
	s = blobmsg_open_table(&blob, "table");
	blobmsg_add_string(&blob, "element1", "string data");
	blobmsg_add_u8(&blob, "element2", true);
	blobmsg_add_u32(&blob, "element3", 200);
	blobmsg_close_table(&blob, s);
	ubus_send_reply(ctx, req, blob.head);
	return 0;
}

int output_option(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {

	char data1[256] = {0};
	char data2[256] = {0};
	char data3[256] = {0};

	bool is_option = false;
	//uci get ubus-sample.test.user
	uci_get_option("ubus-sample.test.data1", data1);
	uci_get_option("ubus-sample.test.data2", data2);
	uci_get_option("ubus-sample.test.data3", data3);

	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "data1", data1);
	blobmsg_add_string(&blob, "data2", data2);
	blobmsg_add_string(&blob, "data3", data3);
	ubus_send_reply(ctx, req, blob.head);

	return 0;
}

/* Ubus object methods */
const struct ubus_method ubus_sample_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
	UBUS_METHOD("change_option", change_option, change_option_policy),
	UBUS_METHOD("output_option", output_option, output_option_policy),
};

/* Ubus object type */
struct ubus_object_type ubus_sample_obj_type =
	UBUS_OBJECT_TYPE("ubus_sample_uobj", ubus_sample_methods);

/* Ubus object */
struct ubus_object ubus_sample_object=
{
	.name = "ubus-sample", //objpath
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

int uci_search_option(const char* str) {
	struct uci_context *ctx;
	struct uci_ptr ptr;
	struct uci_element *e;
	char* input_option = NULL;

	char* param = strdup(str);

	ctx = uci_alloc_context();

	if (param == NULL) {
		return FAILED_STRDUP;
	}

	if (ctx == NULL) {
		return FAILED_ALLOC_UCI_CONTEXT;
	}

	strtok(param, ".");			//extract <config>
	strtok(NULL, ".");			//extract <section>
	input_option = strtok(NULL, ".");	//extract <option>

	if (input_option == NULL) {
		return FAILED_EXTRACT_UCI_PARAMETER;
	}

	int lookup_status = uci_lookup_ptr(ctx, &ptr, param, true);

	if (lookup_status != UCI_OK) {
		return lookup_status;
	}

	if (ptr.o != NULL) {
		uci_foreach_element(&ptr.s->options, e) {
			struct uci_option *o = uci_to_option(e);
			if (o->type == UCI_TYPE_STRING || o->type == UCI_TYPE_LIST) {
				if (!strcmp(o->e.name, input_option)) {
					return HIT_UCI_OPTION;
				}
			}
		}
	}

	return UCI_SEARCH_NOT_FOUND;
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

//Function equivalent to the uci commit command.
bool uci_commit_one_package(char* str) {
	struct uci_context *ctx;
	struct uci_ptr ptr;

	char* config = strdup(str);

	ctx = uci_alloc_context();

	if (uci_lookup_ptr(ctx, &ptr, config, true) != UCI_OK) {
		uci_perror(ctx, "uci commit error");
		return false;
	}

	if (ptr.p != 0) {
		if (uci_commit(ctx, &ptr.p, true) != UCI_OK) {
			uci_perror(ctx, "uci commit error");
			return false;
		}
	}

	return true;
}
