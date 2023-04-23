#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

//Source code description Web site URL
//https://utakamo.com/article/openwrt/library/libuci-c.html

void show_option_value(struct uci_ptr ptr);
void show_list_value(struct uci_option *);

int main(int argc, char **argv)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;

	ctx = uci_alloc_context();
	
	if (argc != 2) {
		printf("input argument error! specify uci parameter.\n");
		printf("ex1) uci-sample05 <config>.<section>=<section-type>\n");
		printf("ex2) uci-sample05 <config>.<section>.<option>=<value>\n");
		return 1;
	}

	uci_lookup_ptr(ctx, &ptr, argv[1], true);
	
	if (ptr.value)
		ret = uci_set(ctx, &ptr);
	else {
		printf("Parser error\n");
		ret = UCI_ERR_PARSE;	
	}
	
	if (ret == UCI_OK)
		uci_save(ctx, ptr.p);
	
	uci_free_context(ctx);

	return 0;
}
