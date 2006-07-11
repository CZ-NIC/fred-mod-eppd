#include <stdio.h>
#include <string.h>

#include "epp_common.h"
#include "epp_parser.h"
#include "epp_gen.h"
#include "epp-client.h"

#define MAX_LENGTH	10000
#define MAX_FILE_NAME   256

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

/**
 * Import object from file.
 */
static int
read_ior (const char *filename, char *ior)
{
	FILE         *file;
	int	i;
	char	c;

	if ((file = fopen(filename, "r")) == NULL) {
		return 0;
	}

	for (i = 0; (c = fgetc(file)) != EOF; ior[i++] = c);

	/* terminate string with \0 */
	ior[i] = '\0';

	fclose (file);
	return 1;
}
 
int main(int argc, char *argv[])
{
	void	*corba_globs;
	char	*greeting;
	char	ior[1000];
	int	session;
	epp_lang	lang;
	epp_command_data cdata;
	char text[MAX_LENGTH];
	char quit = 0;
        int ar = 1; 
	cmd_t cmd;
	parser_status	pstat;
	corba_status	cstat;
	gen_status	gstat;

	/* API: init parser */
	epp_parser_init();

	/* API: init corba */
	if (!read_ior("/tmp/ccReg.ref", ior)) {
		fputs("Could not read IOR\n", stderr);
		return 1;
	}
	if ((corba_globs = epp_corba_init(ior)) == NULL) {
		fputs("Error in corba initialization\n", stderr);
		return 1;
	}

	/* API: greeting */
	gstat = epp_gen_greeting("Server ID", &greeting);
	if (gstat != GEN_OK) {
		fputs("Error in greeting generator\n", stderr);
		return 1;
	}
	else {
		puts(greeting);

		/* API: free greeting data */
		epp_free_greeting(greeting);
	}

	session = 0;
	lang = LANG_EN;

	while (1) {
	   if( argc == 1 ) /* interaktivni rezim */
		 {

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
				continue;
		}
		if (quit) break;

		  }
               else
                { 
                  
                  cmd = CMD_FILE;
                  if( ar < argc ) 
                    {
                      openfile(text , argv[ar] );
                      ar ++ ; 
                     } 
                  else {  quit = 1; break;   } 

                }

		bzero(&cdata, sizeof cdata);

		// show file
		if( argc > 1 ) {
			fprintf( stderr ,  "epp_parse_command\n" );
			printf("\n%s\n" ,   text );
		}

		/* API: process command */
		pstat = epp_parse_command(session, "schemas/all-1.0.xsd", text,
				strlen(text), &cdata);
		if (pstat == PARSER_HELLO) {
			gstat = epp_gen_greeting("Server ID", &greeting);
			if (gstat != GEN_OK) {
				fputs("Error when creating epp greeting\n", stderr);
				return 1;
			}
			puts(greeting);

			/* API: free greeting data */
			epp_free_greeting(greeting);
		}
		else if (pstat != PARSER_OK && pstat != PARSER_NOT_VALID) {
			fputs("Parser error\n", stderr);
			continue;
		}
		else {
			char fp[] = "AE:B3:5F:FA:38:80:DB:37:53:6A:3E:D4:55:E2:91:97";
			int logout; // not used

			/* API: corba call */
			cstat = epp_corba_call(corba_globs, &session, &lang, fp, &cdata,
					&logout);

			if (cstat == CORBA_OK) {
				epp_gen	gen;

				/* API: generate response */
				gstat = epp_gen_response(1, "schemas/all-1.0.xsd", lang, &cdata,
						&gen);
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
						puts(gen.response);
						epp_free_gen(&gen);
						break;
					case GEN_EINTERNAL:
						fputs("Internal error when validating response\n", stderr);
						puts(gen.response);
						epp_free_gen(&gen);
						break;
					case GEN_ESCHEMA:
						fputs("Error when parsing schema\n", stderr);
						puts(gen.response);
						epp_free_gen(&gen);
						break;
					case GEN_NOT_VALID:
						fputs("Server response does not validate\n", stderr);
						if (gen.valerr != NULL) {
							CL_FOREACH(gen.valerr) {
								epp_error	*e = CL_CONTENT(gen.valerr);
								fprintf(stderr, "\tElement: %s\n", e->value);
								fprintf(stderr, "\tReason: %s\n", e->reason);
							}
						}
						puts(gen.response);
						epp_free_gen(&gen);
						break;
					default:
						/* GEN_OK */
						puts(gen.response);
						epp_free_gen(&gen);
						break;
				}
			}
			else fputs("Corba call failed\n", stderr);

			/* API: clean up command data */
			epp_command_data_cleanup(&cdata);
		}
	}

	/* API: clean up globs */
	epp_parser_init_cleanup();
	epp_corba_init_cleanup(corba_globs);

	return 0;
}
