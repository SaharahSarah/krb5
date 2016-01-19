/* lib/krb5/krb/parse_host_string.c - Parse host strings into host and port */
/*
 * Copyright 2016 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */
#include "k5-int.h"
#include <stddef.h>
#include <ctype.h>

/*
 * Parse a string containing a host specifier. The expected
 * format for the string is:
 *
 * [host][[:][port]]
 *
 * host and port are optional, though one must be present.
 * host may have brackets around it so that ipv6 is
 * supported.
 *
 * Arguments:
 * host - The host string that should be parsed.
 * default_port - The default port to use if no port is found.
 * host_out - An output pointer for the parsed host, or NULL if no host was
 * specified or an error occured. Must be freed.
 * port_out - An output pointer for the parsed port. Will be 0 on error.
 *
 * Returns 0 on success, otherwise an error.
 */
krb5_error_code
k5_parse_host_string(const char *host, int default_port, char **host_out,
                  int *port_out)
{
    int     ret, i_port;
    char   *hp, *cp, *port;
    char   *p_host = NULL;
    ptrdiff_t s_host;

    *host_out = NULL;
    *port_out = 0;

    if (default_port < 0 || default_port > 65535) {
        ret = EINVAL;
        goto cleanup;
    }

    /* If the string is empty or just not there, then set the port to the
     * default. */
    if (!host || *host == '\0') {
        *port_out = default_port;
        ret = 0;
        goto cleanup;
    }

    hp = (char *) host;
    /* Find port number, and strip off any excess characters. */
    if (k5_is_string_numeric(host)) {
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
        unsigned long l;
        char   *endptr;
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
        i_port = l;
    } else {
        i_port = default_port;
    }

    /* Copy the host if it was specified. */
    if (hp != NULL && cp != NULL) {
        s_host = cp - hp + 1;

        if (s_host > 1) {
            /* Remove the closing bracket if present. */
            if (hp[s_host - 2] == ']')
                s_host--;

            p_host = (char *) malloc(s_host);
            if (p_host == NULL) {
                ret = ENOMEM;
                goto cleanup;
            }
            memcpy(p_host, hp, s_host);
            p_host[s_host - 1] = '\0';
        }
    }

    *host_out = p_host;
    *port_out = i_port;
    p_host = NULL;
    ret = 0;

  cleanup:
    free(p_host);
    return ret;
}

/*
 * Check if a string is composed solely of digits.
 *
 * Arguments:
 * s - The string to check. May be NULL.
 *
 * returns 1 if the string is all numeric, 0 otherwise.
 */
int
k5_is_string_numeric(const char *s)
{
    size_t  length;
    size_t  i;

    if (s == NULL || *s == '\0')
        return 0;

    length = strlen(s);
    for (i = 0; i < length; i++)
        if (!isdigit(s[i]))
            return 0;

    return 1;
}
