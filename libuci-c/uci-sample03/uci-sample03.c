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
		uci_free_context(ctx);
		return 1;
	}

	//検索成功　中身を表示します。
	/****************************************/
	/*	uci_ptr member variables	*/
	/****************************************/
	
	printf("\n---[Search Results]---\n");
	if (ptr.p != 0) {
		printf(" --package info\n");
		printf("   [uci_element] e.list.next     :%p\n", ptr.p->e.list.next);
		printf("   [uci_element] e.list.prev     :%p\n", ptr.p->e.list.prev);
		printf("   [uci_element] e.name          :%s\n\n", ptr.p->e.name);
		printf("   [uci_list]    sections.next   :%p\n", ptr.p->sections.next);
		printf("   [uci_list]    sections.prev   :%p\n\n", ptr.p->sections.prev);
		printf("   [uci_context] ctx             :%p\n\n", ptr.p->ctx);
	
		printf("   has_delta           :%s\n", (ptr.p->has_delta ? "true" : "false") );
		printf("   path                :%s\n", ptr.p->path);
		printf("   uci_backend address :%p\n", ptr.p->backend);
		printf("   priv                :%p\n", ptr.p->priv);
		printf("   n_section           :%d\n\n", ptr.p->n_section);
		
		printf("   [uci_list] delta.next          :%p\n", ptr.p->delta.next);
		printf("   [uci_list] delta.prev          :%p\n", ptr.p->delta.prev);
		printf("   [uci_list] saved_delta.next    :%p\n", ptr.p->saved_delta.next);
		printf("   [uci_list] saved_delta.prev    :%p\n\n", ptr.p->saved_delta.prev);
	}
	
	if (ptr.s != 0) {
		printf(" --section info\n");
		printf("   [uci_element] e.list.next :%p\n", ptr.s->e.list.next);
		printf("   [uci_element] e.list.prev :%p\n", ptr.s->e.list.prev);
		printf("   [uci_element] e.name      :%s\n\n", ptr.s->e.name);
		
		printf("   [uci_list] options.next   :%p\n", ptr.s->options.next);
		printf("   [uci_list] options.prev   :%p\n\n", ptr.s->options.prev);
		
		printf("   package address :%p\n", ptr.p);
		printf("   anonymous       :%s\n", (ptr.s->anonymous ? "true" : "false"));
		printf("   type            :%s\n\n", ptr.s->type);
	}
	
	if (ptr.o != 0) {
		printf(" --option info\n");
		printf("   [uci_element] e.list.next :%p\n", ptr.o->e.list.next);
		printf("   [uci_element] e.list.prev :%p\n", ptr.o->e.list.prev);
		printf("   [uci_element] e.name :%s\n\n", ptr.o->e.name);
	
		printf("   section address :%p\n", ptr.o->section);
		printf("   option type     :");
		
		switch(ptr.o->type) {
			case UCI_TYPE_STRING:
				printf("UCI_TYPE_STRING\n");
				break;
				
			case UCI_TYPE_LIST:
				printf("UCI_TYPE_LIST\n");
				break;
		}
		
		if(ptr.o->type == UCI_TYPE_STRING) {
			printf("   option value      :%s\n\n", ptr.o->v.string);
		}
		
		if(ptr.o->type == UCI_TYPE_LIST) {
			printf("   [uci_list] list next :%p\n", ptr.o->v.list.next);
			printf("   [uci_list] list prev :%p\n\n", ptr.o->v.list.prev);
		}
	}
	
	if (ptr.last != 0) {
		printf(" --last info\n");
		printf("   [uci_element] list.next :%p\n", ptr.last->list.next);
		printf("   [uci_element] list.prev :%p\n", ptr.last->list.prev);
		printf("   [uci_element] name :%s\n\n", ptr.last->name);
	}
	
	uci_free_context (ctx);
	return 0;
}
