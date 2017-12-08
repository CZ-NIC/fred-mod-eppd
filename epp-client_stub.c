/*  
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epp-client.h"

/**
 * Needed for corba function calls.
 *   - corba is global corba object
 *   - service is ccReg object handle
 */
struct epp_corba_globs_t
{
    int v1;
    int v2;
};

epp_corba_globs* epp_corba_init(const char* ior)
{
    epp_corba_globs* globs;
    if ((globs = malloc(sizeof *globs)) == NULL)
    {
        return NULL;
    }

    return globs;
}

void epp_corba_init_cleanup(epp_corba_globs* globs)
{
    free(globs);
}

corba_status epp_call_dummy(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");

    return CORBA_OK;
}

corba_status epp_call_login(
        epp_corba_globs* globs, int* session, epp_lang* lang, epp_command_data* cdata, char* certID)
{
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;
    *session = 1;
    *lang = cdata->in->login.lang;

    return CORBA_OK;
}

corba_status epp_call_logout(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;

    return CORBA_OK;
}

/**
 * <check> for different objects is so much similar that it is worth of
 * having the code in one function and create just wrappers for different
 * kinds of objects.
 */
static corba_status
epp_call_check(epp_corba_globs* globs, int session, epp_command_data* cdata, epp_object_type obj)
{
    corba_status ret;
    int i;

    ret = CORBA_OK;
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else
    {
        struct circ_list* item;

        if ((cdata->out->check.bools = malloc(sizeof *item)) == NULL)
        {
            free(cdata->out);
            cdata->out = NULL;
            ret = CORBA_INT_ERROR;
        }
        else
        {
            int len;
            CL_NEW(cdata->out->check.bools);
            CL_LENGTH(cdata->in->check.ids, len);
            for (i = 0; i < len; i++)
            {
                item = malloc(sizeof *item);
                /*
					 * note that we cannot use zero value for false value
					 * since value zero of content pointer denotes that
					 * the item in list is a sentinel (first or last).
					 * Therefore we will use value 2 as false value.
					 */
                CL_CONTENT(item) = (void*)1;
                CL_ADD(cdata->out->check.bools, item);
            }
            cdata->svTRID = strdup("fill");
            cdata->msg = strdup("fill");
            cdata->rc = 1000;
        }
    }

    return ret;
}

corba_status epp_call_check_contact(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    return epp_call_check(globs, session, cdata, EPP_CONTACT);
}

corba_status epp_call_check_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    return epp_call_check(globs, session, cdata, EPP_DOMAIN);
}

corba_status epp_call_check_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    return epp_call_check(globs, session, cdata, EPP_NSSET);
}

corba_status epp_call_info_contact(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    epp_postalInfo* pi;
    epp_discl* discl;
    struct circ_list* item;
    corba_status ret;

    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else if ((cdata->out->info_contact.postalInfo = calloc(1, sizeof *pi)) == NULL)
    {
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    else if ((cdata->out->info_contact.discl = calloc(1, sizeof *discl)) == NULL)
    {
        free(cdata->out->info_contact.postalInfo);
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    else if ((cdata->out->info_contact.status = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out->info_contact.postalInfo);
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    /* ok, now everything was successfully allocated */
    else
    {
        cdata->out->info_contact.roid = strdup("fill");
        cdata->out->info_contact.crID = strdup("fill");
        cdata->out->info_contact.upID = strdup("fill");
        cdata->out->info_contact.crDate = 0;
        cdata->out->info_contact.upDate = 0;
        /* contact status */
        CL_NEW(cdata->out->info_contact.status);
        pi = cdata->out->info_contact.postalInfo;
        pi->name = strdup("fill");
        pi->org = strdup("fill");
        pi->street[0] = strdup("fill");
        pi->street[1] = strdup("fill");
        pi->street[2] = strdup("fill");
        pi->city = strdup("fill");
        pi->sp = strdup("fill");
        pi->pc = strdup("fill");
        pi->cc = strdup("fill");
        /* others */
        cdata->out->info_contact.voice = strdup("fill");
        cdata->out->info_contact.fax = strdup("fill");
        cdata->out->info_contact.email = strdup("fill");
        cdata->out->info_contact.notify_email = strdup("fill");
        cdata->out->info_contact.vat = strdup("fill");
        cdata->out->info_contact.ssn = strdup("fill");
        /* disclose info */
        discl = cdata->out->info_contact.discl;
        discl->name = 0;
        discl->org = 0;
        discl->addr = 0;
        discl->voice = 0;
        discl->fax = 0;
        discl->email = 0;

        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
        ret = CORBA_OK;
    }

    return ret;
}

corba_status epp_call_info_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    struct circ_list* item;
    corba_status ret;

    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else if ((cdata->out->info_domain.status = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    else if ((cdata->out->info_domain.admin = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out->info_domain.status);
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    /* ok, now everything was successfully allocated */
    else
    {
        cdata->out->info_domain.roid = strdup("fill");
        cdata->out->info_domain.clID = strdup("fill");
        cdata->out->info_domain.crID = strdup("fill");
        cdata->out->info_domain.upID = strdup("fill");
        cdata->out->info_domain.crDate = 0;
        cdata->out->info_domain.upDate = 0;
        cdata->out->info_domain.trDate = 0;
        cdata->out->info_domain.exDate = 0;

        cdata->out->info_domain.registrant = strdup("fill");
        cdata->out->info_domain.nsset = strdup("fill");
        cdata->out->info_domain.authInfo = strdup("fill");

        /* allocate and initialize status, admin lists */
        CL_NEW(cdata->out->info_domain.status);
        CL_NEW(cdata->out->info_domain.admin);

        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
        ret = CORBA_OK;
    }

    return ret;
}

corba_status epp_call_info_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    struct circ_list* item;
    corba_status ret;

    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else if ((cdata->out->info_nsset.status = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    else if ((cdata->out->info_nsset.ns = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out->info_nsset.status);
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    else if ((cdata->out->info_nsset.tech = malloc(sizeof *item)) == NULL)
    {
        free(cdata->out->info_nsset.ns);
        free(cdata->out->info_nsset.status);
        free(cdata->out);
        cdata->out = NULL;
        ret = CORBA_INT_ERROR;
    }
    /* ok, now alomost everything was successfully allocated */
    else
    {
        cdata->out->info_nsset.roid = strdup("fill");
        cdata->out->info_nsset.clID = strdup("fill");
        cdata->out->info_nsset.crID = strdup("fill");
        cdata->out->info_nsset.upID = strdup("fill");
        cdata->out->info_nsset.crDate = 0;
        cdata->out->info_nsset.upDate = 0;
        cdata->out->info_nsset.trDate = 0;
        cdata->out->info_nsset.authInfo = strdup("fill");

        /* allocate and initialize status list */
        CL_NEW(cdata->out->info_nsset.status);
        /* allocate and initialize tech list */
        CL_NEW(cdata->out->info_nsset.tech);
        /*
			 * allocate and initialize required number of ns items
			 */
        CL_NEW(cdata->out->info_nsset.ns);

        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
        ret = CORBA_OK;
    }

    return ret;
}

corba_status epp_call_poll_req(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else
    {
        cdata->out->poll_req.count = 0;
        cdata->out->poll_req.msgid = 1;
        cdata->out->poll_req.qdate = 0;
        cdata->out->poll_req.msg = strdup("fill");

        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
    }

    return CORBA_OK;
}

corba_status epp_call_poll_ack(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
        ret = CORBA_INT_ERROR;
    else
    {
        cdata->out->poll_ack.count = 0;
        cdata->out->poll_ack.msgid = 1;

        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
    }

    return CORBA_OK;
}

corba_status epp_call_create_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
    {
        return CORBA_INT_ERROR;
    }

    cdata->out->create.crDate = 0;
    cdata->out->create.exDate = 0;

    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;

    return CORBA_OK;
}

corba_status epp_call_create_contact(epp_corba_globs* globs, int session, epp_command_data* cdata)
{

    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
    {
        return CORBA_INT_ERROR;
    }

    cdata->out->create.crDate = 0;
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;

    return CORBA_OK;
}

corba_status epp_call_create_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
    {
        ret = CORBA_INT_ERROR;
    }
    else
    {
        cdata->out->create.crDate = 0;
        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
        ret = CORBA_OK;
    }

    return CORBA_OK;
}

static corba_status
epp_call_delete(epp_corba_globs* globs, int session, epp_command_data* cdata, epp_object_type obj)
{
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;

    return CORBA_OK;
}

corba_status epp_call_delete_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    assert(cdata->in != NULL);
    return epp_call_delete(globs, session, cdata, EPP_DOMAIN);
}

corba_status epp_call_delete_contact(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    assert(cdata->in != NULL);
    return epp_call_delete(globs, session, cdata, EPP_CONTACT);
}

corba_status epp_call_delete_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    assert(cdata->in != NULL);
    return epp_call_delete(globs, session, cdata, EPP_NSSET);
}

corba_status epp_call_renew_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    if ((cdata->out = calloc(1, sizeof(*cdata->out))) == NULL)
    {
        return CORBA_INT_ERROR;
    }
    else
    {
        cdata->out->renew.exDate = 0;
        cdata->svTRID = strdup("fill");
        cdata->msg = strdup("fill");
        cdata->rc = 1000;
    }

    return CORBA_OK;
}

corba_status epp_call_update_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;
    ret = CORBA_OK;
    return ret;
}

corba_status epp_call_update_contact(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;
    ret = CORBA_OK;
    return ret;
}

corba_status epp_call_update_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    corba_status ret;
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;
    ret = CORBA_OK;
    return ret;
}

static corba_status
epp_call_transfer(epp_corba_globs* globs, int session, epp_command_data* cdata, epp_object_type obj)
{
    cdata->svTRID = strdup("fill");
    cdata->msg = strdup("fill");
    cdata->rc = 1000;
    return CORBA_OK;
}

corba_status epp_call_transfer_domain(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    assert(cdata->in != NULL);
    return epp_call_transfer(globs, session, cdata, EPP_DOMAIN);
}

corba_status epp_call_transfer_nsset(epp_corba_globs* globs, int session, epp_command_data* cdata)
{
    assert(cdata->in != NULL);
    return epp_call_transfer(globs, session, cdata, EPP_NSSET);
}
