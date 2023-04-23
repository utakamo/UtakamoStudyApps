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

	ctx = uci_alloc_context();
	
	if (argc != 2) {
		printf ("input argument error! specify uci parameter.\n ex) uci-sample04 network.lan\n");
		return 1;
	}

	uci_lookup_ptr(ctx, &ptr, argv[1], true);
	
	//uci show config.section.option (match)
	if (ptr.o != NULL && ptr.option != NULL) {

		if (ptr.o->type == UCI_TYPE_STRING) {
			printf("%s.%s.%s=%s\n", ptr.p->e.name, ptr.s->e.name, ptr.o->e.name, ptr.o->v.string);
		}
		
		else if (ptr.o->type == UCI_TYPE_LIST) {
			printf("%s.%s.%s=", ptr.p->e.name, ptr.s->e.name, ptr.o->e.name);
			show_list_value(uci_to_option(&ptr.o->e));
		}
	}
		
	//uci show config.section.option (not match)
	else if (ptr.o == NULL && ptr.option != NULL)
		printf("not found\n");
	
	//uci show config.section
	else if (ptr.s != NULL && ptr.option == NULL) 
		show_option_value(ptr);
		
	else
		printf ("specify up to a section.\n");
	
	uci_free_context(ctx);

	return 0;
}

void show_option_value(struct uci_ptr ptr) {
	struct uci_element *e;
	
	uci_foreach_element(&ptr.s->options, e) {
		struct uci_option *o = uci_to_option(e);
		
		if (o->type == UCI_TYPE_STRING) {
			printf("%s.%s.%s=%s\n", ptr.p->e.name, ptr.s->e.name, o->e.name, o->v.string);
		}
		
		else if (o->type == UCI_TYPE_LIST) {
			printf("%s.%s.%s=", ptr.p->e.name, ptr.s->e.name, o->e.name);
			show_list_value(o);
		}
	}
}

void show_list_value(struct uci_option *o) {
	struct uci_element *e;
	uci_foreach_element(&o->v.list, e) {
		//struct uci_option *o = uci_to_option(e);
		//printf("%s ", o->v.string);
		printf("\"%s\" ", e->name);
	}
	printf("\n");
}
