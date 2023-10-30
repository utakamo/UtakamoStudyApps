#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>

void send_event(struct ubus_context *ctx);

int main(int argc, char** argv)
{
	struct ubus_context *ctx = ubus_connect(NULL);

	send_event(ctx);
        ubus_free(ctx);

	return 0;
}

// Ubus send method
// This event can be received by running "ubus listen sample03-event".
void send_event(struct ubus_context *ctx) {
	struct blob_buf blob;
	blob_buf_init(&blob, 0);
	blobmsg_add_string(&blob, "message", "This is a sample event.");
	ubus_send_event(ctx, "sample03-event", blob.head);
}
