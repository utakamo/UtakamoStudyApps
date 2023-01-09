#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;

	if (argc != 2) {
		printf("input argument error!\n ex) uci-sample02 network.lan\n");
		return 1;
	}

	ctx = uci_alloc_context ();

	//今回取り上げるuci_lookup_ptr関数の使い方
	if (uci_lookup_ptr(ctx, &ptr, argv[1], true) != UCI_OK) {
		uci_perror (ctx, "specified args error");
		return 1;
	}

	//検索成功　中身を表示します。
	/****************************************/
	/*	uci_ptr member variables	*/
	/****************************************/

	printf("\"%s\" is exist\n", argv[1]);
	
	switch(ptr.target) {
		case UCI_TYPE_UNSPEC:
			printf("UCI_TYPE_UNSPEC\n");
			break;
			
		case UCI_TYPE_DELTA:
			printf("UCI_TYPE_DELTA\n");
			break;
			
		case UCI_TYPE_PACKAGE:
			printf("UCI_TYPE_PACKAGE\n");
			break;
		case UCI_TYPE_SECTION:
			printf("UCI_TYPE_SECTION\n");
			break;
			
		case UCI_TYPE_OPTION:
			printf("UCI_TYPE_OPTION\n");
			break;
			
		case UCI_TYPE_PATH:
			printf("UCI_TYPE_PATH\n");
			break;
			
		case UCI_TYPE_BACKEND:
			printf("UCI_TYPE_BACKEND\n");
			break;
			
		case UCI_TYPE_ITEM:
			printf("UCI_TYPE_UNSPEC\n");
			break;
			
		case UCI_TYPE_HOOK:
			printf("UCI_TYPE_HOOK\n");
			break;
	}
	
	//ptr->p [uci_package]
	//ptr->s [uci_section]
	//ptr->o [uci_option]
	//ptr->last [uci_element]
	
	printf("package  :%s\n", ptr.package);
	printf("sectioin :%s\n", ptr.section);
	printf("option   :%s\n", ptr.option);
	printf("value    :%s\n", ptr.value);
	
	uci_free_context (ctx);
	return 0;
}
