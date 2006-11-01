#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "epp_common.h"
#include "epp_parser.h"
#include "epp_gen.h"
#include "epp-client.h"

#define MAX_LENGTH	10000
#define MAX_FILE_NAME   256

#define INITIAL_CHUNK 1024
#define MAX_STR_LEN	100000
#define DEBUG_ALLOC 1

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

void *epp_strdup(void *pool, const char *str)
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
			fputs("Maximal allowed cmd lenght exceeded", stderr);
			break;
		}
	}
	cmd[i] = 0;

	if (!strncmp("custom", cmd, 30)) return CMD_CUSTOM;
	if (!strncmp("file", cmd, 30)) return CMD_FILE;
	if (!strncmp("exit", cmd, 30)) return CMD_EXIT;
	return CMD_UNKNOWN;
}

void readinput(char *text)
{
	int c;
	int i = 0;

	fputs("type text: ", stderr);
	while ((c = getchar()) != EOF) {
		text[i++] = (char) c;
		if (i >= MAX_LENGTH - 1) {
			fputs("Maximal allowed text lenght exceeded", stderr);
			break;
		}
	}
	text[i] = 0;
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
	void	*corba_globs;
	char	*greeting;
	int	session;
	epp_lang	lang;
	epp_command_data *cdata;
	char text[MAX_LENGTH];
	char quit = 0;
	cmd_t cmd;
	parser_status	pstat;
	corba_status	cstat;
	gen_status	gstat;
	void	*schema;
	void	*pool;
	int	firsttime;
	int	ar;
	int interactive;
	int	test = 0;
	const char *host = NULL;
	const char *fp = NULL;
	const char *schemafile = NULL;
	int	ret;

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
			case 't':
				test = 1;
				break;
			case 's':
				if (schemafile == NULL && ++ar < argc) schemafile = argv[++ar];
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
		fp = "AE:B3:5F:FA:38:80:DB:37:53:6A:3E:D4:55:E2:91:97";
	if (host == NULL)
		host = "localhost";
	if (schemafile == NULL)
		schemafile = "schemas/all-1.0.xsd";

	if (!test)
		/* API: init parser */
		schema = epp_parser_init(schemafile);

	/* API: init corba */
	if ((corba_globs = epp_corba_init(host, "EPP")) == NULL) {
		fputs("Nameservice error\n", stderr);
		return 2;
	}

	session = 0;
	lang = LANG_EN;
	firsttime = 1;
	ret = 0;

	while (1) {

		if ((pool = create_pool()) == NULL) {
			fputs("Could not create memory pool\n", stderr);
			ret = 1;
			break;
		}

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
					readinput(text);
					break;
				case CMD_FILE:
					if (!readfile(text)) continue;
					puts(text);
					break;
				case CMD_EXIT:
					quit = 1;
					break;
				default:
					fputs("Unknown command\n", stderr);
					destroy_pool(pool);
					continue;
			}
			if (quit) {
				destroy_pool(pool);
				break;
			}
		  }
		  else { 
			  cmd = CMD_FILE;
			  if( ar < argc ) 
			  {
				  openfile(text , argv[ar++] );
			  } 
			  else {
				  destroy_pool(pool);
				  break;
			  } 
		  }

		  // show file
		  if( argc > 1 ) {
			fprintf( stderr ,  "epp_parse_command\n" );
			printf("\n%s\n" ,   text );
		  }

		  /* API: process command */
		  pstat = epp_parse_command(pool, session, schema , text,
				strlen(text), &cdata);
		}

		if (pstat == PARSER_HELLO) {
			char *version;
			char *curdate;

			/* API: greeting */
			if (epp_call_hello(pool, corba_globs, &version, &curdate) == 0) {
				fputs("Corba call failed (greeting)\n", stderr);
				destroy_pool(pool);
				ret = 3;
				break;
			}
			if (test) {
				printf("version: %s, date: %s\n", version, curdate);
				destroy_pool(pool);
				ret = 0;
				break;
			}
			gstat = epp_gen_greeting(pool, version, curdate, &greeting);
			if (gstat != GEN_OK) {
				fputs("Error when creating epp greeting\n", stderr);
				destroy_pool(pool);
				ret = 1;
				break;
			}
			puts(greeting);

			/* API: free greeting data */
			destroy_pool(pool);
			continue;
		}
		else if (pstat == PARSER_CMD_LOGOUT) {
			int logout; // not used

			/* API: corba call */
			cstat = epp_call_logout(pool, corba_globs, session, cdata, &logout);
		}
		else if (pstat == PARSER_CMD_LOGIN) {
			/* API: corba call */
			cstat = epp_call_login(pool, corba_globs, &session, &lang, fp, cdata);
		}
		else if (pstat == PARSER_CMD_OTHER || pstat == PARSER_NOT_VALID) {
			/* API: corba call */
			cstat = epp_call_cmd(pool, corba_globs, session, cdata);
		}
		else {
			fputs("XML PARSER error\n", stderr);
			destroy_pool(pool);
			continue;
		}

		if (cstat == CORBA_OK) {
			char	*response;
			qhead	valerr;

			valerr.body  = NULL;
			valerr.count = 0;

			/* API: generate response */
			gstat = epp_gen_response(pool, 1, schema , lang, cdata,
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
		else fputs("Corba call failed\n", stderr);

		destroy_pool(pool);
	}

	/* API: clean up globs */
	epp_parser_init_cleanup(schema);
	epp_corba_init_cleanup(corba_globs);

	if (ret == 0 && test == 1)
		printf("Exiting without errors\n");
	return ret;
}

/* vim: set ts=4 sw=4: */
