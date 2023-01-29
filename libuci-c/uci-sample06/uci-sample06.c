#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

//Source code description Web site URL
//https://utakamo.com/article/openwrt/library/libuci-c.html

void show_option_value(struct uci_ptr ptr);
void show_list_value(struct uci_option *);

int main (int argc, char **argv)
{
	struct uci_context *ctx = NULL;
	struct uci_package *p = NULL;
	struct uci_section *s = NULL;
	int ret = UCI_OK;

	if (argc != 3) {
		printf ("ex) uci-sample06 <config> <section-type>");
		return 1;
	}

	ctx = uci_alloc_context ();
	
	if ((ret = uci_load(ctx, argv[1], &p)) != UCI_OK)
	{
		uci_free_context (ctx);
		return 1;
	}

	if ((ret = uci_add_section (ctx, p, argv[2], &s)) != UCI_OK)
	{
		uci_free_context (ctx);
		return 1;
	}
	
	if (ret == UCI_OK)
	{
		uci_save (ctx, p);
		printf ("unamed section :%s\n", s->e.name);
	}
	
	uci_free_context (ctx);

	return 0;
}
