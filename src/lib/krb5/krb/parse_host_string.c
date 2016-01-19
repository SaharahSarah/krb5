/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/parse_host_string.c - Parse host strings into host and port */
/*
 * Copyright (C) 2016 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "k5-int.h"
#include <stddef.h>
#include <ctype.h>

/*
 * Parse a string containing a host specifier. The expected
 * format for the string is:
 *
 * host[:port] or port
 *
 * host and port are optional, though one must be present.
 * host may have brackets around it so that ipv6 is
 * supported.
 *
 * Arguments:
 * address - The address string that should be parsed.
 * default_port - The default port to use if no port is found.
 * host_out - An output pointer for the parsed host, or NULL if no host was
 * specified or an error occured. Must be freed.
 * port_out - An output pointer for the parsed port. Will be 0 on error.
 *
 * Returns 0 on success, otherwise an error.
 */
krb5_error_code
k5_parse_host_string(const char *address, int default_port, char **host_out,
                  int *port_out)
{
    int     ret, port_num;
    char   *hp, *cp, *port;
    char   *hostname = NULL;
    ptrdiff_t host_index;
    unsigned long l;
    char   *endptr;

    *host_out = NULL;
    *port_out = 0;

    if (default_port < 0 || default_port > 65535) {
        return EINVAL;
    }

    /* If the string is empty or just not there, then set the port to the
     * default. */
    if (!address || *address == '\0') {
        *port_out = default_port;
        return 0;
    }

    hp = (char *)address;
    /* Find port number, and strip off any excess characters. */
    if (k5_is_string_numeric(address)) {
        port = hp;
        cp = hp = NULL;
    } else {
        if (*hp == '[' && (cp = strchr(hp, ']'))) {
            cp = cp + 1;
            hp++;
        } else {
            cp = hp + strcspn(hp, " \t:");
            /* Check to make sure there are no more colons */
            if (*cp == ':' && strchr(cp + 1, ':')) {
                ret = EINVAL;
                goto cleanup;
            }
        }
        port = (*cp == ':') ? cp + 1 : NULL;
    }

    if (port) {
        /* Parse the port and verify its value. */
        errno = 0;
        l = strtoul(port, &endptr, 10);
        if (errno) {
            ret = errno;
            goto cleanup;
        }
        if (endptr == NULL || *endptr != 0) {
            ret = EINVAL;
            goto cleanup;
        }
        /* L is unsigned, don't need to check <0.  */
        if (l > 65535) {
            ret = EINVAL;
            goto cleanup;
        }
        port_num = l;
    } else {
        port_num = default_port;
    }

    /* Copy the host if it was specified. */
    if (hp != NULL && cp != NULL) {
        host_index = cp - hp + 1;

        if (host_index > 1) {
            /* Remove the closing bracket if present. */
            if (hp[host_index - 2] == ']')
                host_index--;

            hostname = k5memdup0(hp, host_index - 1, &ret);
            if (ret)
                goto cleanup;
        }
    }

    *host_out = hostname;
    *port_out = port_num;
    hostname = NULL;
    ret = 0;

cleanup:
    free(hostname);
    return ret;
}

/*
 * Check if a string is composed solely of digits.
 *
 * Arguments:
 * s - The string to check. May be NULL.
 *
 * returns 1 if the string is all numeric, otherwise 0.
 */
int
k5_is_string_numeric(const char *s)
{
    size_t  i;

    if (s == NULL || *s == '\0')
        return 0;

    for (i = 0; s[i] != '\0'; i++) {
        if (!isdigit(s[i]))
            return 0;
    }

    return 1;
}
