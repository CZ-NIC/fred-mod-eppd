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
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <orbit/orbit.h>
#include <ORBitservices/CosNaming.h>

#include "epp_common.h"
#include "epp_parser.h"
#include "epp_gen.h"
#include "epp-client.h"

#include "epp_common.h"
#include "epp-client.h"
#include "EPP.h"

#define MAX_LENGTH	10000
#define MAX_FILE_NAME   256

#define INITIAL_CHUNK 1024
#define MAX_STR_LEN	100000
/* #define DEBUG_ALLOC 1 */

#define raised_exception(ev)	((ev)->_major != CORBA_NO_EXCEPTION)

/* memory pool structure */
typedef struct {
	qhead	chunks;
#ifdef DEBUG_ALLOC
	unsigned count;
	unsigned bytes;
#endif
}pool_t;

/*
 * Memory Pool routines
 */
static void *create_pool(void)
{
	pool_t	*p;

	p = (pool_t *) calloc(1, sizeof *p);
	if (p == NULL) return NULL;
#ifdef DEBUG_ALLOC
	p->count = 0;
	p->bytes = 0;
#endif
	return (void *) p;
}

static void destroy_pool(void *pool)
{
	pool_t	*p = (pool_t *) pool;
	qitem	*iter;
	qitem	*last;

#ifdef DEBUG_ALLOC
	fprintf(stderr, "Destroying pool:\n");
	fprintf(stderr, "    Allocated:   %8u B\n", p->bytes);
	fprintf(stderr, "    # of allocs: %8u\n", p->count);
#endif

	if ((last = p->chunks.body) != NULL) {
		iter = last->next;
		while (iter != NULL) {
			free(last->content);
			free(last);
			last = iter;
			iter = iter->next;
		}
		free(last->content);
		free(last);
	}
	free(p);
}

static void *epp_alloc(pool_t *p, unsigned size, int prezero)
{
	void	*chunk;
	qitem	*item;
	qitem	*iter;

	chunk = malloc(size);
	if (chunk == NULL)
		return NULL;

	item  = malloc(sizeof *item);
	if (item == NULL) {
		free(chunk);
		return NULL;
	}

	if (prezero)
		memset(chunk, 0, size);

	item->content = chunk;
	item->next = NULL;

	iter = p->chunks.body;
	if (iter == NULL) {
		p->chunks.body = item;
	}
	else {
		while (iter->next != NULL)
			iter = iter->next;
		iter->next = item;
	}
	p->chunks.count++;

#ifdef DEBUG_ALLOC
	p->bytes += size;
	p->count++;
#endif

	return chunk;
}

void *epp_malloc(void *pool, unsigned size)
{
	pool_t *p = (pool_t *) pool;

	return epp_alloc(p, size, 0);
}

void *epp_calloc(void *pool, unsigned size)
{
	pool_t *p = (pool_t *) pool;

	return epp_alloc(p, size, 1);
}

char *epp_strdup(void *pool, const char *str)
{
	pool_t	*p = (pool_t *) pool;
	unsigned	len;
	char	*new_str;

	if (str == NULL)
		return NULL;
	len = strnlen(str, MAX_STR_LEN);
	if (len == MAX_STR_LEN)
		return NULL;
	new_str = (char *) epp_alloc(p, len + 1, 0);
	if (new_str == NULL)
		return NULL;
	memcpy(new_str, str, len);
	new_str[len] = '\0';
	return new_str;
}

char *epp_strcat(void *pool, const char *str1, const char *str2)
{
	pool_t	*p = (pool_t *) pool;
	unsigned	len;
	char	*new_str;

	if (str1 == NULL || str2 == NULL)
		return NULL;
	len = strnlen(str1, MAX_STR_LEN) + strnlen(str2, MAX_STR_LEN);
	if (len >= MAX_STR_LEN)
		return NULL;
	new_str = (char *) epp_alloc(p, len + 1, 0);
	if (new_str == NULL)
		return NULL;
	strncpy(new_str, str1, len);
        new_str[len] = '\0';
	strncat(new_str, str2, (len-strnlen(new_str, MAX_STR_LEN)-1) );
	new_str[len] = '\0';
	return new_str;
}

char *epp_sprintf(void *pool, const char *fmt, ...)
{
	char	buffer[100];
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(buffer, 100, fmt, ap);
	buffer[99] = '\0';
	va_end(ap);

	return epp_strdup(pool, buffer);
}

void epplog(epp_context *epp_ctx, epp_loglevel level, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

ccReg_EPP
get_service(CORBA_ORB orb, const char *ns_loc, const char *obj_name)
{
	ccReg_EPP	service = CORBA_OBJECT_NIL;	/* object's stub */
	CORBA_Environment	ev[1];
	CosNaming_NamingContext	ns; /* used for nameservice */
	CosNaming_NameComponent	*name_component; /* EPP's name */
	CosNaming_Name	*cos_name; /* Cos name used in service lookup */
	char	ns_string[150];

	CORBA_exception_init(ev);

	assert(ns_loc != NULL);
	assert(obj_name != NULL);

	/* build a name of EPP object */
	name_component = CORBA_sequence_CosNaming_NameComponent_allocbuf(2);
	name_component[0].id = CORBA_string_dup("fred");
	name_component[0].kind = CORBA_string_dup("context");
	name_component[1].id = CORBA_string_dup(obj_name);
	name_component[1].kind = CORBA_string_dup("Object");
	cos_name = CosNaming_Name__alloc();
	cos_name->_maximum = cos_name->_length = 2;
	cos_name->_buffer = name_component;
	CORBA_sequence_set_release(cos_name, CORBA_TRUE);

	ns_string[149] = 0;
	snprintf(ns_string, 149, "corbaloc::%s/NameService", ns_loc);
	CORBA_exception_init(ev);

	/* get nameservice */
	ns = (CosNaming_NamingContext) CORBA_ORB_string_to_object(orb, ns_string,ev);
	if (ns == CORBA_OBJECT_NIL || raised_exception(ev)) {
		CORBA_free(cos_name);
		CORBA_exception_free(ev);
		return NULL;
	}
	/* get EPP object */
	service =(ccReg_EPP) CosNaming_NamingContext_resolve(ns, cos_name, ev);
	if (service == CORBA_OBJECT_NIL || raised_exception(ev)) {
		/* release nameservice */
		CORBA_Object_release(ns, ev);
		CORBA_free(cos_name);
		CORBA_exception_free(ev);
		return NULL;
	}
	/* release nameservice */
	CORBA_Object_release(ns, ev);
	CORBA_free(cos_name);
	CORBA_exception_free(ev);

	return service;
}

typedef enum {
	CMD_UNKNOWN,
	CMD_CUSTOM,
	CMD_FILE,
	CMD_EXIT
} cmd_t;

cmd_t getcmd(void)
{
	char cmd[30];
	int c, i;

	i = 0;
	while ((c = getchar()) != '\n') {
		cmd[i++] = (char) c;
		if (i >= 29) {
			fputs("Maximal allowed cmd lenght exceeded\n", stderr);
			break;
		}
	}
	cmd[i] = 0;

	if (!strncmp("custom", cmd, 30)) return CMD_CUSTOM;
	if (!strncmp("file", cmd, 30)) return CMD_FILE;
	if (!strncmp("exit", cmd, 30)) return CMD_EXIT;
	return CMD_UNKNOWN;
}

int readinput(char *text)
{
	int c;
	int i = 0;

	fputs("type text: ", stderr);
	while ((c = getchar()) != EOF) {
		text[i++] = (char) c;
		if (i >= MAX_LENGTH - 1) {
			fputs("Maximal allowed text lenght exceeded\n", stderr);
			return 0;
		}
	}
	text[i] = 0;
	return 1;
}

int readfile(char *text)
{
	int c;
	int i;
	char filename[MAX_FILE_NAME];
	FILE *f;

	fputs("type filename: ", stderr);
	for (i = 0; (c = getchar()) != '\n' && i < MAX_FILE_NAME-1; i++) {
		filename[i] = c;
	}
	filename[i] = 0;

	if ((f = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Could not open file %s\n", filename);
		return 0;
	}
	for (i = 0; (c = fgetc(f)) != EOF && i < MAX_LENGTH - 1; i++) {
		text[i] = c;
	}
	if (i == MAX_LENGTH - 1) {
		fputs("Maximal allowed text lenght exceeded", stderr);
		fclose(f);
		return 0;
	}
	text[i] = 0;
	fclose(f);

	return 1;
}

int openfile(char *text , char *filename )
{
	int c;
	int i;
	FILE *f;


	if ((f = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Could not open file %s\n", filename);
		return 0;
	}
        else   fprintf(stderr, "Open file  %s\n", filename);


	for (i = 0; (c = fgetc(f)) != EOF && i < MAX_LENGTH - 1; i++) {
		text[i] = c;
	}
	if (i == MAX_LENGTH - 1) {
		fputs("Maximal allowed text lenght exceeded", stderr);
	}
	text[i] = 0;
	fclose(f);

	return 1;
}

void usage(void)
{
	fprintf(stderr, "Usage:\n    epp_test [options] [file1 file2 ...]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "      -f fingerprint\n");
	fprintf(stderr, "      -h host\n");
	fprintf(stderr, "      -p\n");
	fprintf(stderr, "      -s schema\n");
	fprintf(stderr, "      -t           (run in test mode)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Return codes:\n");
	fprintf(stderr, "       0    Success\n");
	fprintf(stderr, "       1    Internal error\n");
	fprintf(stderr, "       2    Nameservice failure\n");
	fprintf(stderr, "       3    CORBA call failed\n");
}

int main(int argc, char *argv[])
{
	ccReg_EPP	service;
	CORBA_ORB	orb;
	char	*greeting;
	unsigned long long	loginid;
	epp_lang	lang;
	epp_command_data *cdata;
	char text[MAX_LENGTH];
	char quit;
	cmd_t cmd;
	parser_status	pstat;
	corba_status	cstat;
	gen_status	gstat;
	void	*schema = NULL;
	void	*pool;
	int	firsttime;
	int	ar;
	int interactive;
	int	test = 0;
	int	pflag = 0;
	const char *host = NULL;
	const char *fp = NULL;
	const char *schemafile = NULL;
	int	ret;
	CORBA_Environment ev[1];
	epp_context	epp_ctx;
	epp_red_command_type cmdtype;

	/* parse parameters */
	for (ar = 1; ar < argc; ar++) {
		if (*argv[ar] != '-') break;
		switch (argv[ar][1]) {
			case 'f':
				if (fp == NULL && ++ar < argc) fp = argv[ar];
				else {
					usage();
					return 1;
				}
				break;
			case 'h':
				if (host == NULL && ++ar < argc) host = argv[ar];
				else {
					usage();
					return 1;
				}
				break;
			case 'p':
				pflag = 1;
				break;
			case 't':
				test = 1;
				break;
			case 's':
				if (schemafile == NULL && ++ar < argc) schemafile = argv[ar];
				else {
					usage();
					return 1;
				}
				break;
			default:
				fprintf(stderr, "Unknown option '%s'\n", argv[ar]);
				usage();
				return 1;
		}
	}
	interactive = (ar >= argc);
	if (fp == NULL)
		fp = "60:7E:DF:39:62:C3:9D:3C:EB:5A:87:80:C1:73:4F:99";
	if (host == NULL)
		host = "localhost";
	if (schemafile == NULL)
		schemafile = "schemas/all-1.4.xsd";

	if (!test)
		/* API: init parser */
		schema = epp_parser_init(schemafile);

	/* create orb object */
	CORBA_exception_init(ev);
	orb = CORBA_ORB_init(0, NULL, "orbit-local-orb", ev);
	if (raised_exception(ev)) {
		CORBA_exception_free(ev);
		fputs("ORB initialization error\n", stderr);
		return 2;
	}

	epp_ctx.session = 0;
	epp_ctx.conn = NULL;
	loginid = 0;
	lang = LANG_EN;
	firsttime = 1;
	ret = 0;
	quit = 0;

	while (!quit) {

		if ((pool = create_pool()) == NULL) {
			fputs("Could not create memory pool\n", stderr);
			ret = 1;
			break;
		}

		epp_ctx.pool = pool;

		if ((service = get_service(orb, host, "EPP")) == NULL) {
			fputs("Nameservice error\n", stderr);
			destroy_pool(pool);
			ret = 2;
			break;
		}

		if (pflag) /* just ping the nameservice */
			break;

		if (firsttime) {
			firsttime = 0;
			pstat = PARSER_HELLO;
		}
		else {
		  if (interactive) {

			fputs("Command: ", stderr);
			switch (cmd = getcmd())
					{
				case CMD_CUSTOM:
					if (!readinput(text)) {
						goto epilog;
					}
					break;
				case CMD_FILE:
					if (!readfile(text)) {
						goto epilog;
					}
					puts(text);
					break;
				case CMD_EXIT:
					quit = 1;
					ret = 0;
					goto epilog;
				default:
					fputs("Unknown command\n", stderr);
					destroy_pool(pool);
					continue;
			}
		  }
		  else {
			  cmd = CMD_FILE;
			  if( ar < argc )
			  {
					openfile(text , argv[ar++] );
			  }
			  else {
					quit = 1;
					ret = 0;
					goto epilog;
			  }
		  }

		  // show file
		  if( argc > 1 ) {
			fprintf( stderr ,  "epp_parse_command\n" );
			printf("\n%s\n" ,   text );
		  }

		  /* API: process command */
		  pstat = epp_parse_command(&epp_ctx, (loginid != 0), schema , text,
				strlen(text), &cdata, &cmdtype);
		}

		if (pstat == PARSER_HELLO) {
			char *version;
			char *curdate;

			/* API: greeting */
			if (epp_call_hello(&epp_ctx, service, &version, &curdate) !=CORBA_OK)
			{
				fputs("Corba call failed (greeting)\n", stderr);
				ret = 3;
				quit = 1;
				goto epilog;
			}
			if (test) {
				printf("version: %s, date: %s\n", version, curdate);
				ret = 0;
				quit = 1;
				goto epilog;
			}
			gstat = epp_gen_greeting(pool, version, curdate, &greeting);
			if (gstat != GEN_OK) {
				fputs("Error when creating epp greeting\n", stderr);
				ret = 1;
				quit = 1;
				goto epilog;
			}
			puts(greeting);

			/* API: free greeting data */
			goto epilog;
		}
		else if (pstat == PARSER_CMD_LOGOUT) {
			/* API: corba call */
		    ccReg_TID request_id = 0;
			cstat = epp_call_logout(&epp_ctx, service, &loginid, request_id, cdata);
		} else if (pstat == PARSER_CMD_LOGIN) {
			/* API: corba call */
		    ccReg_TID request_id = 0;
			cstat = epp_call_login(&epp_ctx, service, &loginid, request_id, &lang, fp, cdata);
		}
		else if (pstat == PARSER_CMD_OTHER || pstat == PARSER_NOT_VALID) {
			/* API: corba call */
                    // TODO ugly hack - supply a real ID
			cstat = epp_call_cmd(&epp_ctx, service, loginid, 0, cdata);
		}
		else {
			fputs("XML PARSER error\n", stderr);
			goto epilog;
		}

		if (cstat != CORBA_INT_ERROR) {
			char	*response;
			qhead	valerr;

			valerr.body  = NULL;
			valerr.count = 0;

			/* API: generate response */
			gstat = epp_gen_response(&epp_ctx, 1, schema , lang, cdata,
					&response, &valerr);
			switch (gstat) {
				/*
				 * following errors are serious and response cannot be sent
				 * to client when any of them appears
				 */
				case GEN_EBUFFER:
				case GEN_EWRITER:
				case GEN_EBUILD:
					fputs("XML Generator failed - terminating session\n",stderr);
					break;
				/*
				 * following errors are only informative though serious.
				 * The connection persists and response is sent back to
				 * client.
				 */
				case GEN_NOT_XML:
					fputs("Response is not XML!!\n", stderr);
					puts(response);
					break;
				case GEN_EINTERNAL:
					fputs("Internal error when validating response\n", stderr);
					puts(response);
					break;
				case GEN_ESCHEMA:
					fputs("Error when parsing schema\n", stderr);
					puts(response);
					break;
				case GEN_NOT_VALID:
					fputs("Server response does not validate\n", stderr);
					q_foreach(&valerr) {
						epp_error	*e = q_content(&valerr);
						fprintf(stderr, "\tElement: %s\n", e->value);
						fprintf(stderr, "\tReason: %s\n", e->reason);
					}
					puts(response);
					break;
				default:
					/* GEN_OK */
					puts(response);
					break;
			}
		}
		else fputs("Internal error in Corba part\n", stderr);

epilog:
		CORBA_Object_release(service, ev);
		CORBA_exception_free(ev);
		destroy_pool(pool);
	}

	/* API: clean up globs */
	epp_parser_init_cleanup(schema);
	CORBA_ORB_destroy(orb, ev);
	CORBA_exception_free(ev);

	if (ret == 0 && test == 1)
		printf("Exiting without errors\n");
	return ret;
}

/* vim: set ts=4 sw=4: */
