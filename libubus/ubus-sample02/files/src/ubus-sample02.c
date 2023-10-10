#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

static int reply_cnt;
static void reply_sample_event(struct ubus_context *, struct ubus_event_handler *, const char *, struct blob_attr *);

static void ubus_sample_handle_signal(int signo);
static void ubus_sample_setup_signals(void);
void ubus_process(void);

struct ubus_object ubus_sample_object = {};

const char *event = "sample-event";
struct ubus_event_handler ev = {
	.cb = reply_sample_event,
};

int main () {
	ubus_sample_setup_signals();
	ubus_process();
	return 0;
}

void ubus_process(void) {
	uloop_init();
	struct ubus_context *ctx = ubus_connect(NULL);
	ubus_add_uloop(ctx);
	ubus_add_object(ctx, &ubus_sample_object);
	ubus_register_event_handler(ctx, &ev, event);
	uloop_run();
	uloop_done();
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

static void reply_sample_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *method, struct blob_attr *msg) {
	
	FILE *fp = NULL;
	mkdir("/tmp/ubus-sample02", 0755);

	if ((fp = fopen("/tmp/ubus-sample02/reply", "w")) == NULL) {
		return;
	}

	reply_cnt++;

	fprintf(fp, "count:%d\n", reply_cnt);

	fclose(fp);
}