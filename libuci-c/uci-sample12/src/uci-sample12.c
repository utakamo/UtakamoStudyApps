#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

void commit_one_package(struct uci_context*, char*);
void commit_all_package(struct uci_context*);

int main(int argc, char **argv)
{
	struct uci_context *ctx;
	int ret = UCI_OK;

	ctx = uci_alloc_context();
	
	//target package
	if (argc == 2) {
		commit_one_package(ctx, argv[1]); 
	}
	
	else {
		commit_all_package(ctx);
	}
	
	uci_free_context(ctx);

	return 0;
}

//commit one package
void commit_one_package(struct uci_context *ctx, char* arg) {

	struct uci_ptr ptr;

	if (uci_lookup_ptr(ctx, &ptr, arg, true) != UCI_OK) {
		uci_perror(ctx, "Message");
		return;
	}
	
	if (ptr.p != 0) {
		if (uci_commit(ctx, &ptr.p, true) != UCI_OK) {
			uci_perror(ctx, "Message");
			return;
		}
	}
}

//commit all package
void commit_all_package(struct uci_context *ctx) {

	struct uci_ptr ptr;
	char **configs = NULL;
	char **p;
	
	if ((uci_list_configs(ctx, &configs) != UCI_OK) || !configs) {
		uci_perror(ctx, "Message");
		return;		
	}

	for (p = configs; *p; p++) {
		if (uci_lookup_ptr(ctx, &ptr, *p, true) != UCI_OK) {
			uci_perror(ctx, "Message");
			break;
		}

		if (uci_commit(ctx, &ptr.p, false) != UCI_OK) {
			uci_perror(ctx, "Message");
			break;
		} 
		
		if (ptr.p)
			uci_unload(ctx, ptr.p);
	}
	
	free(configs);
}
