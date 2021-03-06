/*
 * Copyright (C) 2006-2021  CZ.NIC, z. s. p. o.
 *
 * This file is part of FRED.
 *
 * FRED is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FRED is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRED.  If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file epp_gen.c
 *
 * Component for generating greeting frame and responses to EPP commands
 * in form of xml documents.
 *
 * Result of generator is the generated string
 * and validation errors if validation of responses is turned on. Greeting
 * frame is not validated, therefore only string is returned (without the list
 * of validation errors).
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlwriter.h>

#include "epp_common.h"
#include "epp_gen.h"
#include "epp_xmlcommon.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/**
 * @defgroup xmlwritegroup Macros for convenient xml document construction.
 * Following macros are shortcuts used for document creation. So that
 * we don't have to clutter the code with error checking and other stuff.
 * That makes the code much more readable.
 *
 * All macros assume that
 *    - err_handler: parameter is the place where to jump when error occurs
 *    - writer: is is initialized and it is xml writer
 *    - elem: is name of a tag to be written
 *    - str: is value which should be written inside of a tag
 *    - attr_name: is a name of attribute
 *    - attr_value: is a value of an attribute
 *
 * @{
 */

/** Wrapper around libxml's xmlTextWriterStartElement() function. */
#define START_ELEMENT(writer, err_handler, elem)                                                   \
    do                                                                                             \
    {                                                                                              \
        if (xmlTextWriterStartElement(writer, BAD_CAST(elem)) < 0)                                 \
            goto err_handler;                                                                      \
    } while (0)

/** Wrapper around libxml's xmlTextWriterWriteElement() function. */
#define WRITE_ELEMENT(writer, err_handler, elem, str)                                              \
    do                                                                                             \
    {                                                                                              \
        if ((str) != NULL)                                                                         \
            if (xmlTextWriterWriteElement(writer, BAD_CAST(elem), BAD_CAST(str)) < 0)              \
                goto err_handler;                                                                  \
    } while (0)

/** Wrapper around libxml's xmlTextWriterWriteElement() function. */
#define WRITE_ELEMENT_IF_NONEMPTY(writer, err_handler, elem, str)                                  \
    do                                                                                             \
    {                                                                                              \
        if (((str) != NULL) && (*(str) != '\0'))                                                   \
            if (xmlTextWriterWriteElement(writer, BAD_CAST(elem), BAD_CAST(str)) < 0)              \
                goto err_handler;                                                                  \
    } while (0)

/** Wrapper around libxml's xmlTextWriterWriteString() function. */
#define WRITE_STRING(writer, err_handler, str)                                                     \
    do                                                                                             \
    {                                                                                              \
        if ((str) != NULL)                                                                         \
            if (xmlTextWriterWriteString(writer, BAD_CAST(str)) < 0)                               \
                goto err_handler;                                                                  \
    } while (0)

/** Wrapper around libxml's xmlTextWriterWriteAttribute() function. */
#define WRITE_ATTRIBUTE(writer, err_handler, attr_name, attr_value)                                \
    do                                                                                             \
    {                                                                                              \
        if ((attr_value) != NULL)                                                                  \
            if (xmlTextWriterWriteAttribute(writer, BAD_CAST(attr_name), BAD_CAST(attr_value)) <   \
                0)                                                                                 \
                goto err_handler;                                                                  \
    } while (0)

/** Wrapper around libxml's xmlTextWriterEndElement() function. */
#define END_ELEMENT(writer, err_handler)                                                           \
    do                                                                                             \
    {                                                                                              \
        if (xmlTextWriterEndElement(writer) < 0)                                                   \
            goto err_handler;                                                                      \
    } while (0)

/**
 * @}
 */

gen_status epp_gen_greeting(
        void *pool,
        const char *svid,
        const char *date,
        const eppd_server_xml_conf *xml_schema,
        char **greeting)
{
    xmlBufferPtr buf;
    xmlTextWriterPtr writer;
    int error_seen = 1;

    assert(svid != NULL);
    assert(xml_schema != NULL);

    buf = xmlBufferCreate();
    if (buf == NULL)
    {
        return GEN_EBUFFER;
    }
    writer = xmlNewTextWriterMemory(buf, 0);
    if (writer == NULL)
    {
        xmlBufferFree(buf);
        return GEN_EWRITER;
    }

    if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0)
        goto greeting_err;

    /* epp header */
    START_ELEMENT(writer, greeting_err, "epp");
    WRITE_ATTRIBUTE(writer, greeting_err, "xmlns", NS_EPP);
    WRITE_ATTRIBUTE(writer, greeting_err, "xmlns:xsi", XSI);
    WRITE_ATTRIBUTE(writer, greeting_err, "xsi:schemaLocation", LOC_EPP);

    /* greeting part */
    START_ELEMENT(writer, greeting_err, "greeting");
    WRITE_ELEMENT(writer, greeting_err, "svID", svid);
    WRITE_ELEMENT(writer, greeting_err, "svDate", date);
    START_ELEMENT(writer, greeting_err, "svcMenu");
    WRITE_ELEMENT(writer, greeting_err, "version", "1.0");
    WRITE_ELEMENT(writer, greeting_err, "lang", "en");
    WRITE_ELEMENT(writer, greeting_err, "lang", "cs");
    WRITE_ELEMENT(writer, greeting_err, "objURI", NS_CONTACT);
    WRITE_ELEMENT(writer, greeting_err, "objURI", NS_DOMAIN);
    WRITE_ELEMENT(writer, greeting_err, "objURI", NS_NSSET);
    WRITE_ELEMENT(writer, greeting_err, "objURI", NS_KEYSET);
    START_ELEMENT(writer, greeting_err, "svcExtension");
    /* not yet
    WRITE_ELEMENT(writer, greeting_err, "extURI", NS_SECDNS);
    */
    WRITE_ELEMENT(writer, greeting_err, "extURI", NS_ENUMVAL);
    if (xml_schema->has_contact_mailing_address_extension)
    {
        WRITE_ELEMENT(writer, greeting_err, "extURI", NS_EXTRAADDR);
    }
    END_ELEMENT(writer, greeting_err); /* svcExtension */
    END_ELEMENT(writer, greeting_err); /* svcMenu */
    /* dcp part */
    START_ELEMENT(writer, greeting_err, "dcp");
    START_ELEMENT(writer, greeting_err, "access");
    switch (xml_schema->data_collection_policy_access)
    {
        case dcpa_all:
            START_ELEMENT(writer, greeting_err, "all");
            break;
        case dcpa_none:
            START_ELEMENT(writer, greeting_err, "none");
            break;
        default:
            goto greeting_err;
    }
    END_ELEMENT(writer, greeting_err);
    END_ELEMENT(writer, greeting_err);
    START_ELEMENT(writer, greeting_err, "statement");
    START_ELEMENT(writer, greeting_err, "purpose");
    START_ELEMENT(writer, greeting_err, "admin");
    END_ELEMENT(writer, greeting_err);
    START_ELEMENT(writer, greeting_err, "prov");
    END_ELEMENT(writer, greeting_err);
    END_ELEMENT(writer, greeting_err);
    START_ELEMENT(writer, greeting_err, "recipient");
    START_ELEMENT(writer, greeting_err, "public");
    END_ELEMENT(writer, greeting_err);
    END_ELEMENT(writer, greeting_err);
    START_ELEMENT(writer, greeting_err, "retention");
    START_ELEMENT(writer, greeting_err, "stated");

    /* this has side effect of flushing document to buffer */
    if (xmlTextWriterEndDocument(writer) < 0)
        goto greeting_err;

    error_seen = 0;

greeting_err:
    xmlFreeTextWriter(writer);
    if (!error_seen)
    {
        /* successful end */
        *greeting = epp_strdup(pool, (char *)buf->content);
        xmlBufferFree(buf);
        return GEN_OK;
    }

    /* failure */
    xmlBufferFree(buf);
    *greeting = NULL;
    return GEN_EBUILD;
}

static unsigned char does_enabled_discloseflag_differ_from_default_policy(
        unsigned char is_enabled,
        epp_PrivacyPolicy discloseflag,
        epp_PrivacyPolicy default_policy)
{
    return is_enabled && (discloseflag != default_policy);
}

/**
 * This is assistant function for generating info contact <resData>
 * xml subtree.
 *
 * @param writer   XML writer.
 * @param info_contact    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char gen_info_contact(
        xmlTextWriterPtr writer,
        epps_info_contact *info_contact,
        const eppd_server_xml_conf *xml_schema)
{
    START_ELEMENT(writer, simple_err, "contact:infData");
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
    WRITE_ELEMENT(writer, simple_err, "contact:id", info_contact->handle);
    WRITE_ELEMENT(writer, simple_err, "contact:roid", info_contact->roid);
    q_foreach(&info_contact->status)
    {
        epp_status *status;

        status = q_content(&info_contact->status);
        START_ELEMENT(writer, simple_err, "contact:status");
        WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
        WRITE_STRING(writer, simple_err, status->text);
        END_ELEMENT(writer, simple_err);
    }
    // postal info
    START_ELEMENT(writer, simple_err, "contact:postalInfo");
    WRITE_ELEMENT(writer, simple_err, "contact:name", info_contact->pi.name);
    WRITE_ELEMENT(writer, simple_err, "contact:org", info_contact->pi.org);
    START_ELEMENT(writer, simple_err, "contact:addr");
    q_foreach(&info_contact->pi.streets)
    {
        WRITE_ELEMENT(writer, simple_err, "contact:street", q_content(&info_contact->pi.streets));
    }
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:city", info_contact->pi.city);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:sp", info_contact->pi.sp);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:pc", info_contact->pi.pc);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:cc", info_contact->pi.cc);
    END_ELEMENT(writer, simple_err); /* addr */
    END_ELEMENT(writer, simple_err); /* postal info */
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:voice", info_contact->voice);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:fax", info_contact->fax);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:email", info_contact->email);
    WRITE_ELEMENT(writer, simple_err, "contact:clID", info_contact->clID);
    WRITE_ELEMENT(writer, simple_err, "contact:crID", info_contact->crID);
    WRITE_ELEMENT(writer, simple_err, "contact:crDate", info_contact->crDate);
    WRITE_ELEMENT(writer, simple_err, "contact:upID", info_contact->upID);
    WRITE_ELEMENT(writer, simple_err, "contact:upDate", info_contact->upDate);
    WRITE_ELEMENT(writer, simple_err, "contact:trDate", info_contact->trDate);
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:authInfo", info_contact->authInfo);

    epp_PrivacyPolicy default_policy;
    switch (xml_schema->data_collection_policy_access)
    {
    case dcpa_all:
        default_policy = public_data;
        break;
    case dcpa_none:
        default_policy = private_data;
        break;
    default:
        goto simple_err;
    }
    const epp_controlled_privacy_data_mask enabled_disclose_elements = xml_schema->contact_info_available_disclose_elements;
    epp_controlled_privacy_data_mask to_generate;
    to_generate.name = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.name,
            info_contact->discl.name,
            default_policy);
    to_generate.organization = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.organization,
            info_contact->discl.organization,
            default_policy);
    to_generate.address = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.address,
            info_contact->discl.address,
            default_policy);
    to_generate.telephone = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.telephone,
            info_contact->discl.telephone,
            default_policy);
    to_generate.fax = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.fax,
            info_contact->discl.fax,
            default_policy);
    to_generate.email = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.email,
            info_contact->discl.email,
            default_policy);
    to_generate.vat = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.vat,
            info_contact->discl.vat,
            default_policy);
    to_generate.ident = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.ident,
            info_contact->discl.ident,
            default_policy);
    to_generate.notify_email = does_enabled_discloseflag_differ_from_default_policy(
            enabled_disclose_elements.notify_email,
            info_contact->discl.notify_email,
            default_policy);
    /* output disclose section if it is not empty */
    if (to_generate.name ||
        to_generate.organization ||
        to_generate.address ||
        to_generate.telephone ||
        to_generate.fax ||
        to_generate.email ||
        to_generate.vat ||
        to_generate.ident ||
        to_generate.notify_email)
    {
        START_ELEMENT(writer, simple_err, "contact:disclose");
        WRITE_ATTRIBUTE(writer, simple_err, "flag", default_policy == public_data ? "0" : "1");
        if (to_generate.name)
        {
            START_ELEMENT(writer, simple_err, "contact:name");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.organization)
        {
            START_ELEMENT(writer, simple_err, "contact:org");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.address)
        {
            START_ELEMENT(writer, simple_err, "contact:addr");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.telephone)
        {
            START_ELEMENT(writer, simple_err, "contact:voice");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.fax)
        {
            START_ELEMENT(writer, simple_err, "contact:fax");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.email)
        {
            START_ELEMENT(writer, simple_err, "contact:email");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.vat)
        {
            START_ELEMENT(writer, simple_err, "contact:vat");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.ident)
        {
            START_ELEMENT(writer, simple_err, "contact:ident");
            END_ELEMENT(writer, simple_err);
        }
        if (to_generate.notify_email)
        {
            START_ELEMENT(writer, simple_err, "contact:notifyEmail");
            END_ELEMENT(writer, simple_err);
        }
        END_ELEMENT(writer, simple_err); /* contact:disclose */
    }
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:vat", info_contact->vat);
    if ((info_contact->ident != NULL) && (info_contact->ident[0] != '\0'))
    {
        char type[15];

        switch (info_contact->identtype)
        {
            case ident_OP:
                snprintf(type, 15, "%s", "op");
                break;
            case ident_PASSPORT:
                snprintf(type, 15, "%s", "passport");
                break;
            case ident_MPSV:
                snprintf(type, 15, "%s", "mpsv");
                break;
            case ident_ICO:
                snprintf(type, 15, "%s", "ico");
                break;
            case ident_BIRTHDAY:
                snprintf(type, 15, "%s", "birthday");
                break;
            default:
                /*
                 * what should we do? We will create
                 * nonvalidating document.
                 */
                snprintf(type, 15, "%s", "unknown");
                break;
        }
        type[14] = '\0'; /* just to be sure */
        START_ELEMENT(writer, simple_err, "contact:ident");
        WRITE_ATTRIBUTE(writer, simple_err, "type", type);
        WRITE_STRING(writer, simple_err, info_contact->ident);
        END_ELEMENT(writer, simple_err); /* ident */
    }
    WRITE_ELEMENT_IF_NONEMPTY(writer, simple_err, "contact:notifyEmail", info_contact->notify_email);
    END_ELEMENT(writer, simple_err); /* infdata */
    return 1;

simple_err:
    return 0;
}

/**
 * This is assistant function for generating info domain <resData>
 * xml subtree.
 *
 * @param writer   XML writer.
 * @param info_domain    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char gen_info_domain(xmlTextWriterPtr writer, epps_info_domain *info_domain)
{
    START_ELEMENT(writer, simple_err, "domain:infData");
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
    WRITE_ELEMENT(writer, simple_err, "domain:name", info_domain->handle);
    WRITE_ELEMENT(writer, simple_err, "domain:roid", info_domain->roid);
    q_foreach(&info_domain->status)
    {
        epp_status *status;

        status = q_content(&info_domain->status);
        START_ELEMENT(writer, simple_err, "domain:status");
        WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
        WRITE_STRING(writer, simple_err, status->text);
        END_ELEMENT(writer, simple_err);
    }
    WRITE_ELEMENT(writer, simple_err, "domain:registrant", info_domain->registrant);
    q_foreach(&info_domain->admin)
    {
        WRITE_ELEMENT(writer, simple_err, "domain:admin", q_content(&info_domain->admin));
    }
    WRITE_ELEMENT(writer, simple_err, "domain:nsset", info_domain->nsset);
    WRITE_ELEMENT(writer, simple_err, "domain:keyset", info_domain->keyset);
    WRITE_ELEMENT(writer, simple_err, "domain:clID", info_domain->clID);
    WRITE_ELEMENT(writer, simple_err, "domain:crID", info_domain->crID);
    WRITE_ELEMENT(writer, simple_err, "domain:crDate", info_domain->crDate);
    WRITE_ELEMENT(writer, simple_err, "domain:upID", info_domain->upID);
    WRITE_ELEMENT(writer, simple_err, "domain:upDate", info_domain->upDate);
    WRITE_ELEMENT(writer, simple_err, "domain:exDate", info_domain->exDate);
    WRITE_ELEMENT(writer, simple_err, "domain:trDate", info_domain->trDate);
    WRITE_ELEMENT(writer, simple_err, "domain:authInfo", info_domain->authInfo);
    q_foreach(&info_domain->tmpcontact)
    {
        WRITE_ELEMENT(
                writer, simple_err, "domain:tempcontact", q_content(&info_domain->tmpcontact));
    }
    END_ELEMENT(writer, simple_err); /* infdata */
    return 1;

simple_err:
    return 0;
}

/**
 * This is assistant function for generating info nsset <resData>
 * xml subtree.
 *
 * @param writer   XML writer.
 * @param info_nsset    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char gen_info_nsset(xmlTextWriterPtr writer, epps_info_nsset *info_nsset)
{
    char level[3]; /* sufficient for reportlevel */

    START_ELEMENT(writer, simple_err, "nsset:infData");
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
    WRITE_ELEMENT(writer, simple_err, "nsset:id", info_nsset->handle);
    WRITE_ELEMENT(writer, simple_err, "nsset:roid", info_nsset->roid);
    /* status flags */
    q_foreach(&info_nsset->status)
    {
        epp_status *status;

        status = q_content(&info_nsset->status);
        START_ELEMENT(writer, simple_err, "nsset:status");
        WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
        WRITE_STRING(writer, simple_err, status->text);
        END_ELEMENT(writer, simple_err);
    }
    WRITE_ELEMENT(writer, simple_err, "nsset:clID", info_nsset->clID);
    WRITE_ELEMENT(writer, simple_err, "nsset:crID", info_nsset->crID);
    WRITE_ELEMENT(writer, simple_err, "nsset:crDate", info_nsset->crDate);
    WRITE_ELEMENT(writer, simple_err, "nsset:upID", info_nsset->upID);
    WRITE_ELEMENT(writer, simple_err, "nsset:upDate", info_nsset->upDate);
    WRITE_ELEMENT(writer, simple_err, "nsset:trDate", info_nsset->trDate);
    WRITE_ELEMENT(writer, simple_err, "nsset:authInfo", info_nsset->authInfo);
    /* print nameservers */
    q_foreach(&info_nsset->ns)
    {
        epp_ns *ns;

        ns = (epp_ns *)q_content(&info_nsset->ns);
        START_ELEMENT(writer, simple_err, "nsset:ns");
        WRITE_ELEMENT(writer, simple_err, "nsset:name", ns->name);
        /* print addrs of nameserver */
        q_foreach(&ns->addr)
        {
            WRITE_ELEMENT(writer, simple_err, "nsset:addr", q_content(&ns->addr));
        }
        END_ELEMENT(writer, simple_err); /* ns */
    }
    /* print tech contacts */
    q_foreach(&info_nsset->tech)
    {
        WRITE_ELEMENT(writer, simple_err, "nsset:tech", q_content(&info_nsset->tech));
    }
    snprintf(level, 3, "%d", info_nsset->level);
    WRITE_ELEMENT(writer, simple_err, "nsset:reportlevel", level);
    END_ELEMENT(writer, simple_err); /* infdata */
    return 1;

simple_err:
    return 0;
}

/**
 * This is assistant function for generating info keyset <resData>
 * xml subtree.
 *
 * @param writer   XML writer.
 * @param info_keyset    Data needed to generate XML.
 * @return         1 if OK, 0 in case of failure.
 */
static char gen_info_keyset(xmlTextWriterPtr writer, epps_info_keyset *info_keyset)
{
    START_ELEMENT(writer, simple_err, "keyset:infData");
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
    WRITE_ELEMENT(writer, simple_err, "keyset:id", info_keyset->handle);
    WRITE_ELEMENT(writer, simple_err, "keyset:roid", info_keyset->roid);
    /* status flags */
    q_foreach(&info_keyset->status)
    {
        epp_status *status;

        status = q_content(&info_keyset->status);
        START_ELEMENT(writer, simple_err, "keyset:status");
        WRITE_ATTRIBUTE(writer, simple_err, "s", status->value);
        WRITE_STRING(writer, simple_err, status->text);
        END_ELEMENT(writer, simple_err);
    }
    WRITE_ELEMENT(writer, simple_err, "keyset:clID", info_keyset->clID);
    WRITE_ELEMENT(writer, simple_err, "keyset:crID", info_keyset->crID);
    WRITE_ELEMENT(writer, simple_err, "keyset:crDate", info_keyset->crDate);
    WRITE_ELEMENT(writer, simple_err, "keyset:upID", info_keyset->upID);
    WRITE_ELEMENT(writer, simple_err, "keyset:upDate", info_keyset->upDate);
    WRITE_ELEMENT(writer, simple_err, "keyset:trDate", info_keyset->trDate);
    WRITE_ELEMENT(writer, simple_err, "keyset:authInfo", info_keyset->authInfo);
    /* print dnskey records */
    q_foreach(&info_keyset->keys)
    {
        epp_dnskey *key;
        char str[10];

        key = (epp_dnskey *)q_content(&info_keyset->keys);
        START_ELEMENT(writer, simple_err, "keyset:dnskey");

        snprintf(str, 9, "%d", key->flags);
        WRITE_ELEMENT(writer, simple_err, "keyset:flags", str);
        snprintf(str, 9, "%d", key->protocol);
        WRITE_ELEMENT(writer, simple_err, "keyset:protocol", str);
        snprintf(str, 9, "%d", key->alg);
        WRITE_ELEMENT(writer, simple_err, "keyset:alg", str);
        WRITE_ELEMENT(writer, simple_err, "keyset:pubKey", key->public_key);

        END_ELEMENT(writer, simple_err); /* dnskey */
    }

    /* print tech contacts */
    q_foreach(&info_keyset->tech)
    {
        WRITE_ELEMENT(writer, simple_err, "keyset:tech", q_content(&info_keyset->tech));
    }
    END_ELEMENT(writer, simple_err); /* infdata */
    return 1;

simple_err:
    return 0;
}

/**
 * This is assistant function for generating poll message.
 *
 * @param writer    XML writer.
 * @param msgdata   Message data plus its type.
 * @return          1 if OK, 0 in case of failure.
 */
static char gen_poll_message(
        xmlTextWriterPtr writer,
        epps_poll_req *msgdata,
        const eppd_server_xml_conf *xml_schema)
{
    switch (msgdata->type)
    {
        case pt_transfer_contact:
            START_ELEMENT(writer, simple_err, "contact:trnData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
            WRITE_ELEMENT(writer, simple_err, "contact:id", msgdata->msg.hdt.handle);
            WRITE_ELEMENT(writer, simple_err, "contact:trDate", msgdata->msg.hdt.date);
            WRITE_ELEMENT(writer, simple_err, "contact:clID", msgdata->msg.hdt.clID);
            END_ELEMENT(writer, simple_err); /* trnData */
            break;
        case pt_transfer_nsset:
            START_ELEMENT(writer, simple_err, "nsset:trnData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
            WRITE_ELEMENT(writer, simple_err, "nsset:id", msgdata->msg.hdt.handle);
            WRITE_ELEMENT(writer, simple_err, "nsset:trDate", msgdata->msg.hdt.date);
            WRITE_ELEMENT(writer, simple_err, "nsset:clID", msgdata->msg.hdt.clID);
            END_ELEMENT(writer, simple_err); /* trnData */
            break;
        case pt_transfer_keyset:
            START_ELEMENT(writer, simple_err, "keyset:trnData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
            WRITE_ELEMENT(writer, simple_err, "keyset:id", msgdata->msg.hdt.handle);
            WRITE_ELEMENT(writer, simple_err, "keyset:trDate", msgdata->msg.hdt.date);
            WRITE_ELEMENT(writer, simple_err, "keyset:clID", msgdata->msg.hdt.clID);
            END_ELEMENT(writer, simple_err); /* trnData */
            break;
        case pt_transfer_domain:
            START_ELEMENT(writer, simple_err, "domain:trnData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:name", msgdata->msg.hdt.handle);
            WRITE_ELEMENT(writer, simple_err, "domain:trDate", msgdata->msg.hdt.date);
            WRITE_ELEMENT(writer, simple_err, "domain:clID", msgdata->msg.hdt.clID);
            END_ELEMENT(writer, simple_err); /* trnData */
            break;
        case pt_delete_contact:
            START_ELEMENT(writer, simple_err, "contact:idleDelData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
            WRITE_ELEMENT(writer, simple_err, "contact:id", msgdata->msg.handle);
            END_ELEMENT(writer, simple_err); /* idleDelData */
            break;
        case pt_delete_nsset:
            START_ELEMENT(writer, simple_err, "nsset:idleDelData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
            WRITE_ELEMENT(writer, simple_err, "nsset:id", msgdata->msg.handle);
            END_ELEMENT(writer, simple_err); /* idleDelData */
            break;
        case pt_delete_keyset:
            START_ELEMENT(writer, simple_err, "keyset:idleDelData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
            WRITE_ELEMENT(writer, simple_err, "keyset:id", msgdata->msg.handle);
            END_ELEMENT(writer, simple_err); /* idleDelData */
            break;
        case pt_delete_domain:
            START_ELEMENT(writer, simple_err, "domain:delData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "domain:exDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /* delData */
            break;
        case pt_impexpiration:
            START_ELEMENT(writer, simple_err, "domain:impendingExpData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "domain:exDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /* impendingExpData */
            break;
        case pt_expiration:
            START_ELEMENT(writer, simple_err, "domain:expData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "domain:exDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /* expData */
            break;
        case pt_impvalidation:
            START_ELEMENT(writer, simple_err, "enumval:impendingValExpData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:enumval", NS_ENUMVAL);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_ENUMVAL);
            WRITE_ELEMENT(writer, simple_err, "enumval:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "enumval:valExDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /*impendingValExpData*/
            break;
        case pt_validation:
            START_ELEMENT(writer, simple_err, "enumval:valExpData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:enumval", NS_ENUMVAL);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_ENUMVAL);
            WRITE_ELEMENT(writer, simple_err, "enumval:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "enumval:valExDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /* valExpData */
            break;
        case pt_outzone:
            START_ELEMENT(writer, simple_err, "domain:dnsOutageData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:name", msgdata->msg.hd.handle);
            WRITE_ELEMENT(writer, simple_err, "domain:exDate", msgdata->msg.hd.date);
            END_ELEMENT(writer, simple_err); /* dnsOutageData */
            break;
        case pt_techcheck:
            START_ELEMENT(writer, simple_err, "nsset:testData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
            WRITE_ELEMENT(writer, simple_err, "nsset:id", msgdata->msg.tc.handle);
            q_foreach(&msgdata->msg.tc.fqdns)
            {
                WRITE_ELEMENT(writer, simple_err, "nsset:name", q_content(&msgdata->msg.tc.fqdns));
            }
            q_foreach(&msgdata->msg.tc.tests)
            {
                epp_testResult *tr = q_content(&msgdata->msg.tc.tests);
                START_ELEMENT(writer, simple_err, "nsset:result");
                WRITE_ELEMENT(writer, simple_err, "nsset:testname", tr->testname);
                WRITE_ELEMENT(writer, simple_err, "nsset:status", (tr->status ? "true" : "false"));
                WRITE_ELEMENT(writer, simple_err, "nsset:note", tr->note);
                END_ELEMENT(writer, simple_err); /* result */
            }
            END_ELEMENT(writer, simple_err); /* testData */
            break;
        case pt_lowcredit:
        {

            START_ELEMENT(writer, simple_err, "fred:lowCreditData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:fred", NS_FRED);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_FRED);
            WRITE_ELEMENT(writer, simple_err, "fred:zone", msgdata->msg.lc.zone);
            /*
             * XXX
             * this stupid code will be simplified after the
             * schemas will be corrected.
             */
            START_ELEMENT(writer, simple_err, "fred:limit");
            WRITE_ELEMENT(writer, simple_err, "fred:zone", msgdata->msg.lc.zone);

            WRITE_ELEMENT(writer, simple_err, "fred:credit", msgdata->msg.lc.limit);
            END_ELEMENT(writer, simple_err); /* limit */
            START_ELEMENT(writer, simple_err, "fred:credit");
            WRITE_ELEMENT(writer, simple_err, "fred:zone", msgdata->msg.lc.zone);

            WRITE_ELEMENT(writer, simple_err, "fred:credit", msgdata->msg.lc.credit);
            END_ELEMENT(writer, simple_err); /* credit */
            END_ELEMENT(writer, simple_err); /* lowCreditData */
            break;
        }
        case pt_request_fee_info:
        {
            char number[50];

            START_ELEMENT(writer, simple_err, "fred:requestFeeInfoData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:fred", NS_FRED);
            WRITE_ELEMENT(writer, simple_err, "fred:periodFrom", msgdata->msg.rfi.period_from);
            WRITE_ELEMENT(writer, simple_err, "fred:periodTo", msgdata->msg.rfi.period_to);
            snprintf(number, 49, "%llu", msgdata->msg.rfi.total_free_count);
            WRITE_ELEMENT(writer, simple_err, "fred:totalFreeCount", number);
            snprintf(number, 49, "%llu", msgdata->msg.rfi.used_count);
            WRITE_ELEMENT(writer, simple_err, "fred:usedCount", number);
            WRITE_ELEMENT(writer, simple_err, "fred:price", msgdata->msg.rfi.price);
            END_ELEMENT(writer, simple_err);
            break;
        }
        case pt_update_contact:
        {
            START_ELEMENT(writer, simple_err, "contact:updateData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
            WRITE_ELEMENT(writer, simple_err, "contact:opTRID", msgdata->msg.upc.optrid);
            START_ELEMENT(writer, simple_err, "contact:oldData");
            if (!gen_info_contact(writer, &msgdata->msg.upc.old_data, xml_schema))
            {
                goto simple_err;
            }
            END_ELEMENT(writer, simple_err);
            START_ELEMENT(writer, simple_err, "contact:newData");
            if (!gen_info_contact(writer, &msgdata->msg.upc.new_data, xml_schema))
            {
                goto simple_err;
            }
            END_ELEMENT(writer, simple_err);
            END_ELEMENT(writer, simple_err);
            break;
        }
        case pt_update_domain:
        {
            START_ELEMENT(writer, simple_err, "domain:updateData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
            WRITE_ELEMENT(writer, simple_err, "domain:opTRID", msgdata->msg.upd.optrid);
            START_ELEMENT(writer, simple_err, "domain:oldData");
            if (!gen_info_domain(writer, &msgdata->msg.upd.old_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            START_ELEMENT(writer, simple_err, "domain:newData");
            if (!gen_info_domain(writer, &msgdata->msg.upd.new_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            END_ELEMENT(writer, simple_err);
            break;
        }
        case pt_update_nsset:
        {
            START_ELEMENT(writer, simple_err, "nsset:updateData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
            WRITE_ELEMENT(writer, simple_err, "nsset:opTRID", msgdata->msg.upn.optrid);
            START_ELEMENT(writer, simple_err, "nsset:oldData");
            if (!gen_info_nsset(writer, &msgdata->msg.upn.old_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            START_ELEMENT(writer, simple_err, "nsset:newData");
            if (!gen_info_nsset(writer, &msgdata->msg.upn.new_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            END_ELEMENT(writer, simple_err);
            break;
        }
        case pt_update_keyset:
        {
            START_ELEMENT(writer, simple_err, "keyset:updateData");
            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
            WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
            WRITE_ELEMENT(writer, simple_err, "keyset:opTRID", msgdata->msg.upk.optrid);
            START_ELEMENT(writer, simple_err, "keyset:oldData");
            if (!gen_info_keyset(writer, &msgdata->msg.upk.old_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            START_ELEMENT(writer, simple_err, "keyset:newData");
            if (!gen_info_keyset(writer, &msgdata->msg.upk.new_data))
                goto simple_err;
            END_ELEMENT(writer, simple_err);
            END_ELEMENT(writer, simple_err);
            break;
        }
        default:
            START_ELEMENT(writer, simple_err, "fred:lowCreditData");
            break;
    }
    return 1;

simple_err:
    return 0;
}

/**
 * Function gets element (including its content) from input XML document
 * which caused an error. This must be done according to EPP standard.
 *
 * @param pool   Pool to allocate memory from.
 * @param cdata  Command data containing xpath context and parsed document.
 * @param e      Error specification.
 */
static char *get_bad_xml(void *pool, epp_command_data *cdata, epp_error *e)
{
    char *loc_spec;

    switch (e->spec)
    {
        case errspec_poll_msgID:
            loc_spec = epp_strdup(pool, "//epp:poll");
            break;
        case errspec_contact_handle:
            loc_spec = epp_strdup(pool, "//contact:id");
            break;
        case errspec_contact_cc:
            loc_spec = epp_strdup(pool, "//contact:cc");
            break;
        case errspec_nsset_handle:
            loc_spec = epp_strdup(pool, "//nsset:id");
            break;
        case errspec_nsset_tech:
            loc_spec = epp_strdup(pool, "//nsset:tech");
            break;
        case errspec_nsset_dns_name:
            loc_spec = epp_strdup(pool, "//nsset:name");
            break;
        case errspec_nsset_dns_addr:
            loc_spec = epp_strdup(pool, "//nsset:addr");
            break;
        case errspec_nsset_dns_name_add:
            loc_spec = epp_strdup(pool, "//nsset:name");
            break;
        case errspec_nsset_dns_name_rem:
            loc_spec = epp_strdup(pool, "//nsset:rem/nsset:name");
            break;
        case errspec_nsset_tech_add:
            loc_spec = epp_strdup(pool, "//nsset:add/nsset:tech");
            break;
        case errspec_nsset_tech_rem:
            loc_spec = epp_strdup(pool, "//nsset:rem/nsset:tech");
            break;
        case errspec_keyset_handle:
            loc_spec = epp_strdup(pool, "//keyset:id");
            break;
        case errspec_keyset_tech:
            loc_spec = epp_strdup(pool, "//keyset:tech");
            break;
        case errspec_keyset_dnskey_add:
            loc_spec = epp_strdup(pool, "//keyset:add/keyset:dnskey");
            break;
        case errspec_keyset_dnskey_rem:
            loc_spec = epp_strdup(pool, "//keyset:rem/keyset:dnskey");
            break;
        case errspec_keyset_dnskey:
            loc_spec = epp_strdup(pool, "//keyset:dnskey");
            break;
        case errspec_keyset_tech_add:
            loc_spec = epp_strdup(pool, "//keyset:add/keyset:tech");
            break;
        case errspec_keyset_tech_rem:
            loc_spec = epp_strdup(pool, "//keyset:rem/keyset:tech");
            break;
        case errspec_domain_fqdn:
            loc_spec = epp_strdup(pool, "//domain:name");
            break;
        case errspec_domain_registrant:
            loc_spec = epp_strdup(pool, "//domain:registrant");
            break;
        case errspec_domain_nsset:
            loc_spec = epp_strdup(pool, "//domain:nsset");
            break;
        case errspec_domain_keyset:
            loc_spec = epp_strdup(pool, "//domain:keyset");
            break;
        case errspec_domain_period:
            loc_spec = epp_strdup(pool, "//domain:period");
            break;
        case errspec_domain_admin:
            loc_spec = epp_strdup(pool, "//domain:admin");
            break;
        case errspec_domain_tmpcontact:
            loc_spec = epp_strdup(pool, "//domain:tempcontact");
            break;
        case errspec_domain_ext_valDate:
            loc_spec = epp_strdup(pool, "//enumval:valExDate");
            break;
        case errspec_domain_ext_valDate_missing:
            loc_spec = epp_strdup(pool, "/epp:epp");
            break;
        case errspec_domain_curExpDate:
            loc_spec = epp_strdup(pool, "//domain:curExpDate");
            break;
        case errspec_domain_admin_add:
            loc_spec = epp_strdup(pool, "//domain:add/domain:admin");
            break;
        case errspec_domain_admin_rem:
            loc_spec = epp_strdup(pool, "//domain:rem/domain:admin");
            break;
        case errspec_poll_msgID_missing:
            loc_spec = epp_strdup(pool, "//epp:poll");
            break;
        case errspec_contact_identtype_missing:
            loc_spec = epp_strdup(pool, "//contact:ident");
            break;
        case errspec_transfer_op:
            loc_spec = epp_strdup(pool, "//epp:transfer");
            break;
        default:
            loc_spec = epp_strdup(pool, "/epp:epp");
            break;
    }
    return epp_getSubtree(pool, cdata, loc_spec, e->position);
}

gen_status epp_gen_response(
        epp_context *epp_ctx, int validate, void *schema, epp_lang lang, epp_command_data *cdata,
        char **response, qhead *valerr)
{
    xmlTextWriterPtr writer;
    xmlBufferPtr buf;
    char res_code[5];
    char error_seen = 1;

    assert(epp_ctx != NULL);
    assert(schema != NULL);
    assert(cdata != NULL);
    assert(valerr->body == NULL);

    /* initialize default return values */
    *response = NULL;

    /* make up response */
    buf = xmlBufferCreate();
    if (buf == NULL)
    {
        return GEN_EBUFFER;
    }
    writer = xmlNewTextWriterMemory(buf, 0);
    if (writer == NULL)
    {
        xmlBufferFree(buf);
        return GEN_EWRITER;
    }

    if (xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL) < 0)
        goto simple_err;

    /* epp header */
    START_ELEMENT(writer, simple_err, "epp");
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns", NS_EPP);
    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:xsi", XSI);
    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_EPP);

    /* epp response */
    START_ELEMENT(writer, simple_err, "response");
    START_ELEMENT(writer, simple_err, "result");
    snprintf(res_code, 5, "%d", cdata->rc);
    WRITE_ATTRIBUTE(writer, simple_err, "code", res_code);
    START_ELEMENT(writer, simple_err, "msg");
    if (lang != LANG_EN)
        WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
    WRITE_STRING(writer, simple_err, cdata->msg);
    END_ELEMENT(writer, simple_err); /* msg */
    q_foreach(&cdata->errors)
    {
        epp_error *e;

        e = (epp_error *)q_content(&cdata->errors);
        START_ELEMENT(writer, simple_err, "extValue");
        /*
         * we cannot use standard macro WRITE_ELEMENT because we want
         * to preserve <,> chars, otherwise they would be substituted
         * by &lt;, &gt; respectively.
         */
        START_ELEMENT(writer, simple_err, "value");
        if (e->spec != errspec_not_valid)
            e->value = get_bad_xml(epp_ctx->pool, cdata, e);
        if (xmlTextWriterWriteRaw(writer, BAD_CAST e->value) < 0)
            goto simple_err;
        END_ELEMENT(writer, simple_err); /* value */
        START_ELEMENT(writer, simple_err, "reason");
        if (lang != LANG_EN)
            WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
        WRITE_STRING(writer, simple_err, e->reason);
        END_ELEMENT(writer, simple_err); /* reason */
        END_ELEMENT(writer, simple_err); /* extValue */
    }
    END_ELEMENT(writer, simple_err); /* result */

    /* print message queue data if command was poll_<something> */
    if (cdata->type == EPP_POLL_REQ)
    {
        epps_poll_req *poll_req;
        char strbuf[25]; /* is enough number */

        poll_req = cdata->data;
        if (poll_req->count > 0)
        {
            START_ELEMENT(writer, simple_err, "msgQ");
            snprintf(strbuf, 25, "%llu", poll_req->count);
            WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
            WRITE_ATTRIBUTE(writer, simple_err, "id", poll_req->msgid);
            WRITE_ELEMENT(writer, simple_err, "qDate", poll_req->qdate);
            START_ELEMENT(writer, simple_err, "msg");
            if (!gen_poll_message(writer, poll_req, &(cdata->xml_schema)))
            {
                goto simple_err;
            }
            END_ELEMENT(writer, simple_err); /* msg */
            END_ELEMENT(writer, simple_err); /* msgQ */
        }
    }
    else if (cdata->type == EPP_POLL_ACK)
    {
        epps_poll_ack *poll_ack;
        char strbuf[25]; /* is enough number */

        poll_ack = cdata->data;
        if (poll_ack->count > 0)
        {
            START_ELEMENT(writer, simple_err, "msgQ");
            snprintf(strbuf, 25, "%llu", poll_ack->count);
            WRITE_ATTRIBUTE(writer, simple_err, "count", strbuf);
            WRITE_ATTRIBUTE(writer, simple_err, "id", poll_ack->newmsgid);
            END_ELEMENT(writer, simple_err); /* msgQ */
        }
    }

    /* If there is no resdata section then skip the switch alltogether */
    if (!cdata->noresdata)
    {
        START_ELEMENT(writer, simple_err, "resData");
        /* beware - the indentation is broken here */

        /*
         * Here is handler for each kind of response
         * Short reponses are coded directly into switch, long responses
         * are coded into separate functions called within the switch.
         */
        switch (cdata->type)
        {
            /* commands with no <resData> element */
            /*
        case EPP_DUMMY:
        case EPP_LOGIN:
        case EPP_LOGOUT:
        case EPP_POLL_ACK:
        case EPP_POLL_REQ:
        case EPP_DELETE_DOMAIN:
        case EPP_DELETE_CONTACT:
        case EPP_DELETE_NSSET:
        case EPP_UPDATE_DOMAIN:
        case EPP_UPDATE_CONTACT:
        case EPP_UPDATE_NSSET:
        case EPP_TRANSFER_DOMAIN:
        case EPP_TRANSFER_CONTACT:
        case EPP_TRANSFER_NSSET:
        case EPP_SENDAUTHINFO_DOMAIN:
        case EPP_SENDAUTHINFO_CONTACT:
        case EPP_SENDAUTHINFO_NSSET:
        case EPP_SENDAUTHINFO_KEYSET:
        case EPP_TEST_NSSET:
            break;
        */
            /* query commands with <resData> element */
            case EPP_CHECK_DOMAIN:
            {
                epps_check *check;

                check = cdata->data;
                START_ELEMENT(writer, simple_err, "domain:chkData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
                q_reset(&check->avails);
                q_foreach(&check->ids)
                {
                    epp_avail *avail;

                    avail = q_content(&check->avails);
                    START_ELEMENT(writer, simple_err, "domain:cd");
                    START_ELEMENT(writer, simple_err, "domain:name");
                    if (avail->avail)
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
                    else
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
                    WRITE_STRING(writer, simple_err, q_content(&check->ids));
                    END_ELEMENT(writer, simple_err); /* name */
                    if (!avail->avail)
                    {
                        START_ELEMENT(writer, simple_err, "domain:reason");
                        if (lang != LANG_EN)
                            WRITE_ATTRIBUTE(writer, simple_err, "lang", "cs");
                        WRITE_STRING(writer, simple_err, avail->reason);
                        END_ELEMENT(writer, simple_err); /* reason */
                    }
                    END_ELEMENT(writer, simple_err); /* cd */
                    q_next(&check->avails);
                }
                END_ELEMENT(writer, simple_err); /* chkData */
                break;
            }
            case EPP_CHECK_CONTACT:
            {
                epps_check *check;

                check = cdata->data;
                START_ELEMENT(writer, simple_err, "contact:chkData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
                q_reset(&check->avails);
                q_foreach(&check->ids)
                {
                    epp_avail *avail;

                    avail = q_content(&check->avails);
                    START_ELEMENT(writer, simple_err, "contact:cd");
                    START_ELEMENT(writer, simple_err, "contact:id");
                    if (avail->avail)
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
                    else
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
                    WRITE_STRING(writer, simple_err, q_content(&check->ids));
                    END_ELEMENT(writer, simple_err); /* name */
                    if (!avail->avail)
                        WRITE_ELEMENT(writer, simple_err, "contact:reason", avail->reason);
                    END_ELEMENT(writer, simple_err); /* cd */
                    q_next(&check->avails);
                }
                END_ELEMENT(writer, simple_err); /* chkData */
                break;
            }
            case EPP_CHECK_NSSET:
            {
                epps_check *check;

                check = cdata->data;
                START_ELEMENT(writer, simple_err, "nsset:chkData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
                q_reset(&check->avails);
                q_foreach(&check->ids)
                {
                    epp_avail *avail;

                    avail = q_content(&check->avails);
                    START_ELEMENT(writer, simple_err, "nsset:cd");
                    START_ELEMENT(writer, simple_err, "nsset:id");
                    if (avail->avail)
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
                    else
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
                    WRITE_STRING(writer, simple_err, q_content(&check->ids));
                    END_ELEMENT(writer, simple_err); /* name */
                    if (!avail->avail)
                        WRITE_ELEMENT(writer, simple_err, "nsset:reason", avail->reason);
                    END_ELEMENT(writer, simple_err); /* cd */
                    q_next(&check->avails);
                }
                END_ELEMENT(writer, simple_err); /* chkData */
                break;
            }
            case EPP_CHECK_KEYSET:
            {
                epps_check *check;

                check = cdata->data;
                START_ELEMENT(writer, simple_err, "keyset:chkData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
                q_reset(&check->avails);
                q_foreach(&check->ids)
                {
                    epp_avail *avail;

                    avail = q_content(&check->avails);
                    START_ELEMENT(writer, simple_err, "keyset:cd");
                    START_ELEMENT(writer, simple_err, "keyset:id");
                    if (avail->avail)
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "1");
                    else
                        WRITE_ATTRIBUTE(writer, simple_err, "avail", "0");
                    WRITE_STRING(writer, simple_err, q_content(&check->ids));
                    END_ELEMENT(writer, simple_err); /* name */
                    if (!avail->avail)
                        WRITE_ELEMENT(writer, simple_err, "keyset:reason", avail->reason);
                    END_ELEMENT(writer, simple_err); /* cd */
                    q_next(&check->avails);
                }
                END_ELEMENT(writer, simple_err); /* chkData */
                break;
            }
            case EPP_INFO_DOMAIN:
                if (!gen_info_domain(writer, (epps_info_domain *)cdata->data))
                    goto simple_err;
                break;
            case EPP_INFO_CONTACT:
                if (!gen_info_contact(writer, (epps_info_contact *)cdata->data, &(cdata->xml_schema)))
                {
                    goto simple_err;
                }
                break;
            case EPP_INFO_NSSET:
                if (!gen_info_nsset(writer, (epps_info_nsset *)cdata->data))
                    goto simple_err;
                break;
            case EPP_INFO_KEYSET:
                if (!gen_info_keyset(writer, (epps_info_keyset *)cdata->data))
                    goto simple_err;
                break;

            /* transform commands with <resData> element */
            case EPP_CREATE_DOMAIN:
            {
                epps_create_domain *create_domain;

                create_domain = cdata->data;
                START_ELEMENT(writer, simple_err, "domain:creData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
                WRITE_ELEMENT(writer, simple_err, "domain:name", create_domain->name);
                WRITE_ELEMENT(writer, simple_err, "domain:crDate", create_domain->crDate);
                WRITE_ELEMENT(writer, simple_err, "domain:exDate", create_domain->exDate);
                END_ELEMENT(writer, simple_err); /* credata */
                break;
            }
            case EPP_CREATE_CONTACT:
            {
                epps_create_contact *create_contact;

                create_contact = cdata->data;
                START_ELEMENT(writer, simple_err, "contact:creData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
                WRITE_ELEMENT(writer, simple_err, "contact:id", create_contact->id);
                WRITE_ELEMENT(writer, simple_err, "contact:crDate", create_contact->crDate);
                END_ELEMENT(writer, simple_err); /* credata */
                break;
            }
            case EPP_CREATE_NSSET:
            {
                epps_create_nsset *create_nsset;

                create_nsset = cdata->data;
                START_ELEMENT(writer, simple_err, "nsset:creData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
                WRITE_ELEMENT(writer, simple_err, "nsset:id", create_nsset->id);
                WRITE_ELEMENT(writer, simple_err, "nsset:crDate", create_nsset->crDate);
                END_ELEMENT(writer, simple_err); /* credata */
                break;
            }
            case EPP_CREATE_KEYSET:
            {
                epps_create_keyset *create_keyset;

                create_keyset = cdata->data;
                START_ELEMENT(writer, simple_err, "keyset:creData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
                WRITE_ELEMENT(writer, simple_err, "keyset:id", create_keyset->id);
                WRITE_ELEMENT(writer, simple_err, "keyset:crDate", create_keyset->crDate);
                END_ELEMENT(writer, simple_err); /* credata */
                break;
            }
            case EPP_RENEW_DOMAIN:
            {
                epps_renew *renew;

                renew = cdata->data;
                START_ELEMENT(writer, simple_err, "domain:renData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
                WRITE_ELEMENT(writer, simple_err, "domain:name", renew->name);
                WRITE_ELEMENT(writer, simple_err, "domain:exDate", renew->exDate);
                END_ELEMENT(writer, simple_err); /* renData */
                break;
            }
            case EPP_LIST_CONTACT:
            {
                epps_list *list;

                list = cdata->data;
                START_ELEMENT(writer, simple_err, "contact:listData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:contact", NS_CONTACT);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_CONTACT);
                q_foreach(&list->handles)
                {
                    WRITE_ELEMENT(writer, simple_err, "contact:id", q_content(&list->handles));
                }
                END_ELEMENT(writer, simple_err); /* listData */
                break;
            }
            case EPP_LIST_DOMAIN:
            {
                epps_list *list;

                list = cdata->data;
                START_ELEMENT(writer, simple_err, "domain:listData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:domain", NS_DOMAIN);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_DOMAIN);
                q_foreach(&list->handles)
                {
                    WRITE_ELEMENT(writer, simple_err, "domain:name", q_content(&list->handles));
                }
                END_ELEMENT(writer, simple_err); /* listData */
                break;
            }
            case EPP_LIST_NSSET:
            {
                epps_list *list;

                list = cdata->data;
                START_ELEMENT(writer, simple_err, "nsset:listData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:nsset", NS_NSSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_NSSET);
                q_foreach(&list->handles)
                {
                    WRITE_ELEMENT(writer, simple_err, "nsset:id", q_content(&list->handles));
                }
                END_ELEMENT(writer, simple_err); /* listData */
                break;
            }
            case EPP_LIST_KEYSET:
            {
                epps_list *list;

                list = cdata->data;
                START_ELEMENT(writer, simple_err, "keyset:listData");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:keyset", NS_KEYSET);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_KEYSET);
                q_foreach(&list->handles)
                {
                    WRITE_ELEMENT(writer, simple_err, "keyset:id", q_content(&list->handles));
                }
                END_ELEMENT(writer, simple_err); /* listData */
                break;
            }
            case EPP_CREDITINFO:
            {
                epps_creditInfo *creditInfo;

                creditInfo = cdata->data;
                START_ELEMENT(writer, simple_err, "fred:resCreditInfo");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:fred", NS_FRED);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_FRED);
                q_foreach(&creditInfo->zonecredits)
                {
                    epp_zonecredit *zonecredit;

                    START_ELEMENT(writer, simple_err, "fred:zoneCredit");
                    zonecredit = q_content(&creditInfo->zonecredits);
                    WRITE_ELEMENT(writer, simple_err, "fred:zone", zonecredit->zone);
                    WRITE_ELEMENT(writer, simple_err, "fred:credit", zonecredit->credit);
                    END_ELEMENT(writer, simple_err); /* zoneCredit */
                }
                END_ELEMENT(writer, simple_err); /* resCreditInfo */
                break;
            }
            case EPP_INFO_LIST_CONTACTS:
            case EPP_INFO_LIST_DOMAINS:
            case EPP_INFO_LIST_NSSETS:
            case EPP_INFO_LIST_KEYSETS:
            case EPP_INFO_DOMAINS_BY_NSSET:
            case EPP_INFO_DOMAINS_BY_KEYSET:
            case EPP_INFO_DOMAINS_BY_CONTACT:
            case EPP_INFO_NSSETS_BY_CONTACT:
            case EPP_INFO_KEYSETS_BY_CONTACT:
            case EPP_INFO_NSSETS_BY_NS:
            {
                epps_info *info;
                char infocount[20];

                info = cdata->data;
                START_ELEMENT(writer, simple_err, "fred:infoResponse");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:fred", NS_FRED);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_FRED);
                snprintf(infocount, 19, "%u", info->count);
                WRITE_ELEMENT(writer, simple_err, "fred:count", infocount);
                END_ELEMENT(writer, simple_err); /* infoResponse */
                break;
            }
            case EPP_INFO_GET_RESULTS:
            {
                epps_list *list;

                list = cdata->data;
                START_ELEMENT(writer, simple_err, "fred:resultsList");
                WRITE_ATTRIBUTE(writer, simple_err, "xmlns:fred", NS_FRED);
                WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_FRED);
                q_foreach(&list->handles)
                {
                    WRITE_ELEMENT(writer, simple_err, "fred:item", q_content(&list->handles));
                }
                END_ELEMENT(writer, simple_err); /* resultsList */
                break;
            }
            default:
                assert(1 == 0);
        } /* end of switch statement */

        END_ELEMENT(writer, simple_err); /* resData */

        /* optional domain extensions */
        if (cdata->type == EPP_INFO_DOMAIN)
        {
            epps_info_domain *info_domain;
            int print_ext;

            info_domain = cdata->data;
            print_ext = 0;
            q_foreach(&info_domain->extensions)
            {
                epp_ext_item *ext_item;

                if (!print_ext)
                {
                    START_ELEMENT(writer, simple_err, "extension");
                    print_ext = 1;
                }
                ext_item = q_content(&info_domain->extensions);
                if (ext_item->extType == EPP_EXT_ENUMVAL)
                {
                    START_ELEMENT(writer, simple_err, "enumval:infData");
                    WRITE_ATTRIBUTE(writer, simple_err, "xmlns:enumval", NS_ENUMVAL);
                    WRITE_ATTRIBUTE(writer, simple_err, "xsi:schemaLocation", LOC_ENUMVAL);
                    WRITE_ELEMENT(
                            writer,
                            simple_err,
                            "enumval:valExDate",
                            ext_item->ext.ext_enum.ext_enumval);
                    if (!ext_item->ext.ext_enum.publish)
                    {
                        WRITE_ELEMENT(writer, simple_err, "enumval:publish", "0");
                    }
                    else
                    {
                        WRITE_ELEMENT(writer, simple_err, "enumval:publish", "1");
                    }

                    /* infdata (enumval) */
                    END_ELEMENT(writer, simple_err);
                }
            }
            if (print_ext)
            {
                END_ELEMENT(writer, simple_err); /* extension */
            }
        } /* ... broken indentation */

        /* optional contact info extensions */
        if (cdata->type == EPP_INFO_CONTACT)
        {
            epps_info_contact *info_contact = cdata->data;
            int print_ext = 0;

            q_foreach(&info_contact->extensions)
            {
                epp_ext_item *ext_item = q_content(&info_contact->extensions);

                if (!print_ext)
                {
                    START_ELEMENT(writer, simple_err, "extension");
                    print_ext = 1;
                }

                switch (ext_item->extType)
                {
                    case EPP_EXT_MAILING_ADDR:
                    {
                        START_ELEMENT(writer, simple_err, "extra-addr:infData");
                        {
                            WRITE_ATTRIBUTE(writer, simple_err, "xmlns:extra-addr", NS_EXTRAADDR);
                            WRITE_ATTRIBUTE(
                                    writer, simple_err, "xsi:schemaLocation", LOC_EXTRAADDR);
                        }
                        START_ELEMENT(writer, simple_err, "extra-addr:mailing");
                        START_ELEMENT(writer, simple_err, "extra-addr:addr");
                        {
                            int any_nonempty_street = 0;
                            if (ext_item->ext.ext_mailing_addr.data.info.Street1 &&
                                (strlen(ext_item->ext.ext_mailing_addr.data.info.Street1) > 0))
                            {
                                WRITE_ELEMENT(
                                        writer,
                                        simple_err,
                                        "extra-addr:street",
                                        ext_item->ext.ext_mailing_addr.data.info.Street1);
                                any_nonempty_street = 1;
                            }
                            if (ext_item->ext.ext_mailing_addr.data.info.Street2 &&
                                (strlen(ext_item->ext.ext_mailing_addr.data.info.Street2) > 0))
                            {
                                WRITE_ELEMENT(
                                        writer,
                                        simple_err,
                                        "extra-addr:street",
                                        ext_item->ext.ext_mailing_addr.data.info.Street2);
                                any_nonempty_street = 1;
                            }
                            if (ext_item->ext.ext_mailing_addr.data.info.Street3 &&
                                (strlen(ext_item->ext.ext_mailing_addr.data.info.Street3) > 0))
                            {
                                WRITE_ELEMENT(
                                        writer,
                                        simple_err,
                                        "extra-addr:street",
                                        ext_item->ext.ext_mailing_addr.data.info.Street3);
                                any_nonempty_street = 1;
                            }

                            /* when the streets are empty... and you need a fix... */
                            if (any_nonempty_street == 0)
                            {
                                WRITE_ELEMENT(writer, simple_err, "extra-addr:street", "");
                            }

                            WRITE_ELEMENT(
                                    writer,
                                    simple_err,
                                    "extra-addr:city",
                                    ext_item->ext.ext_mailing_addr.data.info.City);
                            if (ext_item->ext.ext_mailing_addr.data.info.StateOrProvince &&
                                (ext_item->ext.ext_mailing_addr.data.info.StateOrProvince[0] !=
                                 '\0'))
                            {
                                WRITE_ELEMENT(
                                        writer,
                                        simple_err,
                                        "extra-addr:sp",
                                        ext_item->ext.ext_mailing_addr.data.info.StateOrProvince);
                            }
                            WRITE_ELEMENT(
                                    writer,
                                    simple_err,
                                    "extra-addr:pc",
                                    ext_item->ext.ext_mailing_addr.data.info.PostalCode);
                            WRITE_ELEMENT(
                                    writer,
                                    simple_err,
                                    "extra-addr:cc",
                                    ext_item->ext.ext_mailing_addr.data.info.CountryCode);
                        }
                        END_ELEMENT(writer, simple_err);
                        END_ELEMENT(writer, simple_err);
                        END_ELEMENT(writer, simple_err);
                        break;
                    }
                    /* unknown extension type */
                    default:
                        goto simple_err;
                }
            }
            if (print_ext)
            {
                END_ELEMENT(writer, simple_err); /* </extension> */
            }
        }

    } /* if resdata section */

    /* epp epilog */
    START_ELEMENT(writer, simple_err, "trID");
    WRITE_ELEMENT(writer, simple_err, "clTRID", cdata->clTRID);
    WRITE_ELEMENT(writer, simple_err, "svTRID", cdata->svTRID);

    /* this has side effect of flushing document to buffer */
    if (0 <= xmlTextWriterEndDocument(writer))
    {
        error_seen = 0;
    }
simple_err:
    xmlFreeTextWriter(writer);
    if (error_seen)
    {
        xmlBufferFree(buf);
        return GEN_EBUILD;
    }

    *response = epp_strdup(epp_ctx->pool, (char *)buf->content);
    xmlBufferFree(buf);
    if (*response == NULL)
    {
        return GEN_EBUILD;
    }

    /* optional add on - response validation */
    if (validate)
    {
        /* parse xml request */
        xmlDocPtr doc = xmlParseMemory(*response, strlen(*response));
        if (doc == NULL)
        {
            return GEN_NOT_XML;
        }
        const valid_status val_ret = validate_doc(epp_ctx->pool, (xmlSchemaPtr)schema, doc, valerr);
        xmlFreeDoc(doc);
        switch (val_ret)
        {
            case VAL_OK:
                return GEN_OK;
            case VAL_NOT_VALID:
                return GEN_NOT_VALID;
            case VAL_ESCHEMA:
                return GEN_ESCHEMA;
            case VAL_EINTERNAL:
                return GEN_EINTERNAL;
            default:
                return GEN_EINTERNAL;
        }
    }
    return GEN_OK;
}
