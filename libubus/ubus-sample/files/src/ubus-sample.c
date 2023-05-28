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

/* Enum for GSERVER policy order */
enum {
	UBUS_SAMPLE_ID,
	UBUS_SAMPLE_DATA,
	UBUS_SAMPLE_MSG,
	__UBUS_SAMPLE_MAX,
};

/* Ubus method policy */
static const struct blobmsg_policy greeting_policy[] =
{
	//[UBUS_SAMPLE_STYLE_ID]  = { .name="id", .type=BLOBMSG_TYPE_INT32},
	//[UBUS_SAMPLE_STYLE_DATA] = { .name="data", .type=BLOBMSG_TYPE_INT32 },
	[UBUS_SAMPLE_MSG] = { .name="greeting", .type=BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy config_reload_policy[] = {};

/* ubus methods */
static int greeting(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);
			  
static int config_reload(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg);

void ubus_process(void);

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

void sigterm_handler(int signum)
{
    terminate_flg = true;
}

void sigusr1_handler(int signum)
{
    reload_flg = true;
}

int main(int argc, char** argv)
{
	create_daemon();

	signal(SIGTERM, sigterm_handler);
	signal(SIGUSR1, sigusr1_handler);
	
	ubus_process();

	return EXIT_SUCCESS;
}

// Ubus method functions
//Reload the uci configuration file.
//Execution is triggered at startup and [/etc/init.d/ubus-sample reload].
int greeting(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {
	/* do something */
	return 0;
}

int config_reload(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg) {

	char data[256] = {0};

	bool is_option = false;
	//uci get ubus-sample.test.user
	is_option = uci_get_option("ubus-sample.test.user", data);
	
	
	
	return 0;
}

/* Ubus object methods */
const struct ubus_method ubus_sample_methods[] =
{
	/* UBUS_METHOD(method_name, method_call_function, method_policy) */
	UBUS_METHOD("greeting", greeting, greeting_policy),
	UBUS_METHOD("config_reload", config_reload, config_reload_policy),
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

//Function equivalent to the uci get command.
bool uci_get_option(char* str, char* value){
	struct uci_context *ctx;
	struct uci_ptr ptr;

	char* param = strdup(str);

	ctx = uci_alloc_context();

	if (ctx == NULL)
		return false;

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
