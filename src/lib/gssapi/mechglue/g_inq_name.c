/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright 2009 by the Massachusetts Institute of Technology.
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

/* Glue routine for gss_inquire_name */

#include "mglueP.h"

OM_uint32 KRB5_CALLCONV
gss_inquire_name(OM_uint32 *minor_status,
                 gss_name_t name,
                 int *name_is_MN,
                 gss_OID *MN_mech,
                 gss_buffer_set_t *attrs)
{
    OM_uint32           status, tmp;
    gss_union_name_t    union_name;
    gss_mechanism       mech;
    int i;
    if (minor_status == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    if (name == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME;

    if (MN_mech != NULL)
        *MN_mech = GSS_C_NO_OID;

    if (attrs != NULL)
        *attrs = GSS_C_NO_BUFFER_SET;

    *minor_status = 0;
    union_name = (gss_union_name_t)name;

    status = GSS_S_UNAVAILABLE;
    *minor_status = 0;
    if (name_is_MN != NULL)
        *name_is_MN = 0;

    for (i = 0; i < union_name->num_mechs; i++) {
        if (union_name->mech_type[i] == GSS_C_NO_OID) {
            /* We don't yet support non-mechanism attributes */
            if (name_is_MN != NULL)
                *name_is_MN = 0;
            *minor_status = 0;
            status = GSS_S_COMPLETE;
            continue;
        }

        mech = gssint_get_mechanism(name->mech_type[i]);
        if (mech == NULL) {
            status = GSS_S_BAD_NAME;
            continue;
        }

        if (mech->gss_inquire_name == NULL) {
            status = GSS_S_UNAVAILABLE;
            continue;
        }

        status = (*mech->gss_inquire_name)(minor_status,
                                           union_name->mech_name[i],
                                           NULL,
                                           NULL,
                                           attrs);
        if (status == GSS_S_COMPLETE) {
            if (name_is_MN != NULL)
                *name_is_MN = 1;
            if (MN_mech != NULL) {
                status = generic_gss_copy_oid(minor_status,
                                              union_name->mech_type[i],
                                              MN_mech);
            }
            break;
        }
        map_error(minor_status, mech);
    }

    return status;
}
