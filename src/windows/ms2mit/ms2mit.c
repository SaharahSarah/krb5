/* windows/ms2mit/ms2mit.c */
/*
 * Copyright (C) 2003 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

#include "krb5.h"
#include <stdio.h>
#include <string.h>

extern int optind;
extern char *optarg;

static char *prog;

static void
xusage(void)
{
    fprintf(stderr, "xusage: %s [-c ccache]\n", prog);
    exit(1);
}

/*
 * Returns TRUE if the kerberos principal is the name of a Kerberos ticket
 * service.
 */
static krb5_boolean
is_tgs_principal(krb5_context kcontext, krb5_const_principal principal)
{
    if (krb5_princ_size(kcontext, principal) != 2)
        return FALSE;
    if (data_eq_string(*krb5_princ_component(kcontext, principal, 0),
        KRB5_TGS_NAME))
        return TRUE;
    else
        return FALSE;
}

int
main(int argc, char *argv[])
{
    krb5_context kcontext = NULL;
    krb5_error_code code;
    krb5_ccache ccache = NULL;
    krb5_ccache mslsa_ccache = NULL;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_principal princ = NULL;
    int found_tgt = 0;
    int option;
    char *ccachestr = NULL;
    krb5_ticket *tkt;

    prog = strrchr(argv[0], '/');
    prog = prog ? (prog + 1) : argv[0];

    while ((option = getopt(argc, argv, "c:h")) != -1) {
        switch (option) {
        case 'c':
            ccachestr = optarg;
            break;
        case 'h':
        default:
            xusage();
            break;
        }
    }

    if (code = krb5_init_context(&kcontext)) {
        com_err(argv[0], code, "while initializing kerberos library");
        goto cleanup;
    }

    if (code = krb5_cc_resolve(kcontext, "MSLSA:", &mslsa_ccache)) {
        com_err(argv[0], code, "while opening MS LSA ccache");
        goto cleanup;
    }

    /* Enumerate tickets from cache looking for an initial ticket */
    if ((code = krb5_cc_start_seq_get(kcontext, mslsa_ccache, &cursor))) {
        com_err(argv[0], code, "while initiating the cred sequence of MS LSA ccache");
        goto cleanup;
    }

    while (!found_tgt) {
        code = krb5_cc_next_cred(kcontext, mslsa_ccache, &cursor, &creds);
        if (code)
            break;

        /* Check if the ticket is a TGT */
        if (is_tgs_principal(kcontext, creds.server))
            found_tgt = 1;

        krb5_free_cred_contents(kcontext, &creds);
    }
    krb5_cc_end_seq_get(kcontext, mslsa_ccache, &cursor);

    if (code = krb5_cc_set_flags(kcontext, mslsa_ccache, 0)) {
        com_err(argv[0], code, "while clearing flags");
        goto cleanup;
    }

    if (!found_tgt) {
        fprintf(stderr, "%s: Initial Ticket Getting Tickets are not available from the MS LSA\n",
                argv[0]);
        krb5int_cc_user_set_default_name(kcontext, "MSLSA:");
        code = 1;
        goto cleanup;
    }

    if (code = krb5_cc_get_principal(kcontext, mslsa_ccache, &princ)) {
        com_err(argv[0], code, "while obtaining MS LSA principal");
        goto cleanup;
    }

    if (ccachestr)
        code = krb5_cc_resolve(kcontext, ccachestr, &ccache);
    else
        code = krb5_cc_default(kcontext, &ccache);
    if (code) {
        com_err(argv[0], code, "while getting default ccache");
        ccache = NULL;
        goto cleanup;
    }
    if (code = krb5_cc_initialize(kcontext, ccache, princ)) {
        com_err (argv[0], code, "when initializing ccache");
        goto cleanup;
    }

    if (code = krb5_cc_copy_creds(kcontext, mslsa_ccache, ccache)) {
        com_err (argv[0], code, "while copying MS LSA ccache to default ccache");
        goto cleanup;
    }

cleanup:

    if (princ != NULL)
        krb5_free_principal(kcontext, princ);
    if (ccache != NULL)
        krb5_cc_close(kcontext, ccache);
    if (mslsa_ccache != NULL)
        krb5_cc_close(kcontext, mslsa_ccache);
    if (kcontext != NULL)
        krb5_free_context(kcontext);
    return code;
}
