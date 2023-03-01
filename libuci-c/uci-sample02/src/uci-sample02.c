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

	if (argc != 2) {
		printf ("input argument error!\n ex) uci-sample02 network.lan\n");
		return 1;
	}

	ctx = uci_alloc_context ();

	//How to use uci_lookup_ptr func
	if (uci_lookup_ptr (ctx, &ptr, argv[1], true) != UCI_OK) {
		uci_perror (ctx, "specified args error");
		uci_free_context (ctx);
		return 1;
	}

	//search success
	/****************************************/
	/*	uci_ptr member variables	*/
	/****************************************/

	printf ("\"%s\" is exist\n", argv[1]);
	printf ("argument type :");

	switch (ptr.target) {
		case UCI_TYPE_UNSPEC:
			printf ("UCI_TYPE_UNSPEC\n\n");
			break;

		case UCI_TYPE_DELTA:
			printf ("UCI_TYPE_DELTA\n\n");
			break;

		case UCI_TYPE_PACKAGE:
			printf ("UCI_TYPE_PACKAGE\n\n");
			break;
		case UCI_TYPE_SECTION:
			printf ("UCI_TYPE_SECTION\n\n");
			break;

		case UCI_TYPE_OPTION:
			printf ("UCI_TYPE_OPTION\n\n");
			break;

		case UCI_TYPE_PATH:
			printf ("UCI_TYPE_PATH\n\n");
			break;

		case UCI_TYPE_BACKEND:
			printf ("UCI_TYPE_BACKEND\n\n");
			break;

		case UCI_TYPE_ITEM:
			printf ("UCI_TYPE_UNSPEC\n\n");
			break;

		case UCI_TYPE_HOOK:
			printf ("UCI_TYPE_HOOK\n\n");
			break;
	}

	printf ("----[Input Argument Syntax Parsing Result]---\n");
	printf ("package  :%s\n", ptr.package);
	printf ("sectioin :%s\n", ptr.section);
	printf ("option   :%s\n", ptr.option);
	printf ("value    :%s\n\n", ptr.value);

	printf ("---[Search Result]---\n");
	printf ("package address :%p\n", ptr.p);
	printf ("section address :%p\n", ptr.s);
	printf ("option address  :%p\n", ptr.o);
	printf ("last address    :%p\n\n", ptr.last);

	uci_free_context (ctx);

	return 0;
}
