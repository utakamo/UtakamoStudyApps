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

/* GLOBAL VARIABLE DECLARATION */
bool terminate_flg = false;
bool reload_flg = false;

bool uci_get_option(char*, char*);
bool uci_set_option(char*);

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
	
	reply();

	for (;;) {
		if (terminate_flg)
 			break;
 
 		if (reload_flg) {
 			reply();
 			reload_flg = false;
 		}
 
 		sleep(3);
	}

    return EXIT_SUCCESS;
}

void reply() {
	char user_name[256] = {0};
	char greeting[256] = {0};

	bool is_option = false;

	is_option = uci_get_option("sysv-style.test.user", user_name);

	if (is_option) {
		snprintf(greeting, sizeof(greeting), "sysv-style.test.reply=Hello %s!!", user_name);
		uci_set_option(greeting);
	}
}

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

bool uci_set_option(char* param) {
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;

	ctx = uci_alloc_context();

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
		return -1;
	}

	if (ret == UCI_OK)
		uci_save(ctx, ptr.p);

	uci_free_context(ctx);
	return true;
}
