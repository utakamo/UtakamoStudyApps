#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

//Source code description Web site URL
//https://utakamo.com/article/openwrt/library/libuci-c.html

int main (int argc, char **argv)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;

	ctx = uci_alloc_context ();
	
	if (argc != 2) {
		printf ("[uci_revert]\n");
		printf ("input argument error! specify uci parameter.\n");
		printf ("ex) uci-sample13 <config>.[<section>]\n");
		return 1;
	}

	uci_lookup_ptr (ctx, &ptr, argv[1], true);
	
	if (ptr.p != 0)
		ret = uci_revert (ctx, &ptr);
	else {
		printf ("Parse error\n");
		ret = UCI_ERR_PARSE;	
	}
	
	if (ret == UCI_OK)
		uci_save(ctx, ptr.p);
	
	uci_free_context (ctx);

	return 0;
}
