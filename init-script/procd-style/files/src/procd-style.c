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
#include <uci.h>
#include <libubus.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

/* GLOBAL VARIABLE DECLARATION */
bool terminate_flg = false;
bool reload_flg = false;

void reply();
bool uci_get_option(char*, char*);
bool uci_set_option(char*);
bool uci_commit_one_package(char*);
bool procd_style_ubus_init();
bool procd_style_reload();

static int procd_style_handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	if (!procd_style_reload())
		return UBUS_STATUS_NOT_FOUND;

	return UBUS_STATUS_OK;
}

static struct ubus_method main_object_methods[] = {
    { .name = "reload", .handler = procd_style_handle_reload },
};

static struct ubus_object_type main_object_type = UBUS_OBJECT_TYPE("procd-style", main_object_methods);

static struct ubus_object main_object = {
	.name = "procd-style",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

static void procd_style_setup_signals(void)
{
	struct sigaction s;

	memset(&s, 0, sizeof(s));
	s.sa_handler = procd_style_handle_reload;
	s.sa_flags = 0;
	sigaction(SIGINT, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	sigaction(SIGUSR1, &s, NULL);

	s.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &s, NULL);
}

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

	procd_style_ubus_init();

	uloop_run();

    return EXIT_SUCCESS;
}

//Reload the uci configuration file.
//Execution is triggered at startup and [/etc/init.d/procd-style reload].
void reply() {
	char greeting[256] = {0};
	char user_name[128] = {0};

	bool is_option = false;

	// uci get sysv-style.test.user
	is_option = uci_get_option("procd-style.test.user", user_name);

	if (is_option) {
		// uci set sysv-style.test.reply=Hello
		snprintf(greeting, sizeof(greeting), "procd-style.test.reply=Hello %s!!", user_name);
		uci_set_option(greeting);
		// uci commit sysv-style
		uci_commit_one_package("procd-style");
	}
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

bool procd_style_ubus_init() {
	struct ubus_context *ctx;
	struct ubus_object obj;

	ctx = ubus_connect(NULL);

	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return false;
	}

	//create ubus object
	memset(&obj, 0, sizeof(obj));
	obj.name = "procd-style";
	obj.methods = (struct ubus_method[]) {
		{.name = "reload", .handler = procd_style_handle_reload},
		{}
	};

	//register ubus object
	ubus_add_object(ctx, &obj);

	ubus_free(ctx);

	return true;
}

bool procd_style_reload() {

	char user_name[128] = {0};
	char greeting[256] = {0};

	bool is_option = false;
	//uci get procd-style.test.user
	is_option = uci_get_option("procd-style.test.user", user_name);
	
	if (is_option) {
		// uci set sysv-style.test.reply=Hello
		snprintf(greeting, sizeof(greeting), "procd-style.test.reply=Hello %s!!", user_name);
		uci_set_option(greeting);
		// uci commit sysv-style
		uci_commit_one_package("procd-style");
	}	
	
	return is_option;
}


