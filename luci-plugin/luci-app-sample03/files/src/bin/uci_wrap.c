/*
 * Copyright (C) 2024 utakamo <contact@utakamo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "uci_wrap.h"

/*
* Function equivalent to the uci get command.
*
* usage:
* char value[256];
* uci_get_option("config.section.option", value);
* ---> uci get config.section.option
*
* uci_param format : <config>.<section>.<option>
*
* My Site URL:
* https://utakamo.com/article/openwrt/library/libuci-c.html#uci-sample03
*/
bool uci_get_option(char* uci_param, char* value) {

    struct uci_context *ctx;
    struct uci_ptr ptr;

    char* param = strdup(uci_param);

    ctx = uci_alloc_context();

    if (param == NULL) {
        return false;
    }

    if (ctx == NULL) {
        return false;
    }

    if (uci_lookup_ptr(ctx, &ptr, param, true) != UCI_OK) {
        uci_perror(ctx, "uci set error");
        uci_free_context(ctx);
        return false;
    }

    if (ptr.o != 0 && ptr.o->type == UCI_TYPE_STRING) {
        if (sizeof(value) <= sizeof(ptr.o->v.string)) {
            strcpy(value, ptr.o->v.string);
        }
    }

    uci_free_context(ctx);
    free(param);
    return true;
}

/*
* Function equivalent to the uci set command.
*
* usage:
* uci_set_option("config.section.option=100");
* ---> uci set config.section.option=100
* ---> uci commit config
*
* uci_param format : <config>.<section>.<option>=<value>
*
* note:
* Write data to the staging area(/tmp/.uci) and commit to the static area(/etc/config).
*
* My Site URL:
* https://utakamo.com/article/openwrt/library/libuci-c.html#uci_set
*/
bool uci_set_option(char* uci_param) {

    struct uci_context *ctx;
    struct uci_ptr ptr;
    int ret = UCI_OK;

    ctx = uci_alloc_context();

    char* param = strdup(uci_param);

    if (uci_lookup_ptr(ctx, &ptr, param, true) != UCI_OK) {
        uci_perror(ctx, "uci set error");
        uci_free_context(ctx);
        return false;
    }

    if (ptr.value)
        ret = uci_set(ctx, &ptr);
    else {
        ret = UCI_ERR_PARSE;
        uci_free_context(ctx);
        return false;
    }

    if (ret == UCI_OK) {
        uci_save(ctx, ptr.p);
        uci_commit(ctx, &ptr.p, true);
    }

    uci_free_context(ctx);
    return true;
}