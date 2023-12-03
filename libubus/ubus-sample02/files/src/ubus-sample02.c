#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libubus.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

enum {
	TEST_MESSAGE,
	TEST_MAX
};

static const struct blobmsg_policy test_policy[] = {
	[TEST_MESSAGE] = { .name = "message", .type = BLOBMSG_TYPE_STRING },
};

void ubus_process(void);
static void ubus_sample_handle_signal(int signo);
static void ubus_sample_setup_signals(void);

static int reply_cnt;
static void reply_sample_event(struct ubus_context *, struct ubus_event_handler *, const char *, struct blob_attr *);

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
	ubus_register_event_handler(ctx, &ev, "sample-event");
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

	struct blob_attr *tb[TEST_MESSAGE];
	blobmsg_parse(test_policy, TEST_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[TEST_MESSAGE]) {
		return;
	}

	char *message = blobmsg_get_string(tb[TEST_MESSAGE]);

	FILE *fp = NULL;
	mkdir("/tmp/ubus-sample02", 0755);

	if ((fp = fopen("/tmp/ubus-sample02/reply", "a")) == NULL) {
		return;
	}

	reply_cnt++;

	fprintf(fp, "[count:%d], message = %s\n", reply_cnt, message);

	fclose(fp);
}
