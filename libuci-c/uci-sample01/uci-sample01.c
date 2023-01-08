#include <stdio.h>
#include <string.h>
#include <uci.h>
#include <stdlib.h>

int main (int argc, char **argv)
{
    struct uci_context *c;

    c = uci_alloc_context ();

    printf("\n");
    printf("---list of config packages---\n");
    printf("next package address :%p\n", c->root.next);
    printf("prev package address :%p\n\n", c->root.prev);

    printf("uci runtime flags :");

    switch(c->flags)
    {
    	case UCI_FLAG_STRICT:
    		printf("UCI_FLAG_STRICT\n");
    		break;

    	case UCI_FLAG_PERROR:
    		printf("UCI_FLAG_PERROR\n");
    		break;

    	case UCI_FLAG_EXPORT_NAME:
    		printf("UCI_FLAG_EXPORT\n");
    		break;

    	case UCI_FLAG_SAVED_DELTA:
    		printf("UCI_FLAG_SAVE_DELTA\n");
    		break;
    	default:
    		printf("NO FLAG HIT! (%d)\n", c->flags);
    		break;
    }

    printf("config directory :%s\n", c->confdir);
    printf("savedir directory :%s\n\n", c->savedir);

    printf("---search path for delta files---\n");
    printf("delta path next :%p\n", c->delta_path.next);
    printf("delta path prev :%p\n\n", c->delta_path.prev);

    printf("---private---\n");
    printf("err :%d\n", c->err);
    printf("internal :%s\n", (c->internal ? "true" : "false") );
    printf("nested :%s\n", (c->nested ? "true" : "false") );
    printf("buffer size :%d\n", c->bufsz);

    printf("\n");

    uci_free_context (c);
    return 0;
}
