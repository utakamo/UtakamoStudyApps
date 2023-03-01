#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

//Source code description Web site URL
//https://utakamo.com/article/openwrt/library/libuci-c.html
int main (int argc, char **argv)
{
	struct uci_context *ctx;

	ctx = uci_alloc_context ();

	// output uci_context member
	printf ("\n");
	printf ("---list of config packages---\n");
	printf ("next package address :%p\n", ctx->root.next);
	printf ("prev package address :%p\n\n", ctx->root.prev);

	printf ("uci runtime flags :");

	switch (ctx->flags)
	{
		case UCI_FLAG_STRICT:
			printf ("UCI_FLAG_STRICT\n");
			break;

		case UCI_FLAG_PERROR:
			printf ("UCI_FLAG_PERROR\n");
			break;

		case UCI_FLAG_EXPORT_NAME:
			printf ("UCI_FLAG_EXPORT\n");
			break;

		case UCI_FLAG_SAVED_DELTA:
			printf ("UCI_FLAG_SAVE_DELTA\n");
			break;
		default:
			printf ("NO FLAG HIT! (%d)\n", ctx->flags);
			break;
	}

	printf ("config directory :%s\n", ctx->confdir);
	printf ("savedir directory :%s\n\n", ctx->savedir);

	printf ("---search path for delta files---\n");
	printf ("delta path next :%p\n", ctx->delta_path.next);
	printf ("delta path prev :%p\n\n", ctx->delta_path.prev);

	printf ("---private---\n");
	printf ("err :%d\n", ctx->err);
	printf ("internal :%s\n", (ctx->internal ? "true" : "false") );
	printf ("nested :%s\n", (ctx->nested ? "true" : "false") );
	printf ("buffer size :%d\n", ctx->bufsz);

	printf ("\n");

	uci_free_context (ctx);

	return 0;
}
