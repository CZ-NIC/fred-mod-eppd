#include <stdio.h>
#include <string.h>

#include "epp_common.h"
#include "epp_xml.h"
#include "epp-client.h"

#define MAX_LENGTH	1000

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
	char filename[50];
	FILE *f;

	fputs("type filename: ", stderr);
	for (i = 0; (c = getchar()) != '\n' && i < 49; i++) {
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
	void	*xml_globs;
	void	*corba_globs;
	char	*greeting;
	char	*result;
	char	ior[1000];
	int	session;
	epp_command_data cdata;
	char text[MAX_LENGTH];
	char quit = 0;
	cmd_t cmd;
	parser_status	pstat;
	corba_status	cstat;
	gen_status	gstat;

	/* API: check libxml */
	if ((xml_globs = epp_xml_init("schemas/all-1.0.xsd")) == NULL) {
		fputs("Error in xml initialization\n", stderr);
		return 1;
	}

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
	gstat = epp_gen_greeting("Server ID", "curent:date", &greeting);
	if (gstat != GEN_OK) {
		fputs("Error in greeting generator\n", stderr);
		return 1;
	}
	else {
		puts(greeting);
	}
	/* API: free greeting data */
	epp_free_greeting(greeting);

	session = 0;

	while (1) {
		fputs("Command: ", stderr);
		switch (cmd = getcmd()) {
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

		bzero(&cdata, sizeof cdata);
		/* API: process command */
		pstat = epp_parse_command(session, xml_globs, text, strlen(text),
				&cdata);
		if (pstat != PARSER_OK) {
			fputs("Parser error\n", stderr);
			continue;
		}

		switch (cdata.type) {
			case EPP_LOGIN:
				/* API: call login */
				cstat = epp_call_login(corba_globs, &session, &cdata);
				if (cstat == CORBA_OK) {
					/* API: generate login */
					gstat = epp_gen_login(xml_globs, &cdata, &result);
					if (gstat == GEN_OK) {
						puts(result);
						epp_free_genstring(result);
					}
					else fputs("Generator error\n", stderr);
				}
				else fputs("Corba call failed\n", stderr);
				break;
			case EPP_LOGOUT:
				/* API: call logout */
				cstat = epp_call_logout(corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					/* API: generate logout */
					gstat = epp_gen_logout(xml_globs, &cdata, &result);
					if (gstat == GEN_OK) {
						puts(result);
						epp_free_genstring(result);
					}
					else fputs("Generator error\n", stderr);
				}
				else fputs("Corba call failed\n", stderr);
				break;
			case EPP_DUMMY:
				/* API: call dummy */
				cstat = epp_call_dummy(corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					/* API: generate dummy */
					gstat = epp_gen_dummy(xml_globs, &cdata, &result);
					if (gstat == GEN_OK) {
						puts(result);
						epp_free_genstring(result);
					}
					else fputs("Generator error\n", stderr);
				}
				else fputs("Corba call failed\n", stderr);
				break;
			case EPP_CHECK_CONTACT:
				/* API: call check contact */
				cstat = epp_call_check_contact(corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					/* API: generate check contact */
					gstat = epp_gen_check_contact(xml_globs, &cdata, &result);
					if (gstat == GEN_OK) {
						puts(result);
						epp_free_genstring(result);
					}
					else fputs("Generator error\n", stderr);
				}
				else fputs("Corba call failed\n", stderr);
				break;
			case EPP_CHECK_DOMAIN:
				/* API: call check domain */
				cstat = epp_call_check_domain(corba_globs, session, &cdata);
				if (cstat == CORBA_OK) {
					/* API: generate check domain */
					gstat = epp_gen_check_domain(xml_globs, &cdata, &result);
					if (gstat == GEN_OK) {
						puts(result);
						epp_free_genstring(result);
					}
					else fputs("Generator error\n", stderr);
				}
				else fputs("Corba call failed\n", stderr);
				break;
			default:
				fputs("Unknown epp frame type\n", stderr);
				break;
		}

		/* API: clean up command data */
		epp_command_data_cleanup(&cdata);
	}

	/* API: clean up globs */
	epp_xml_init_cleanup(xml_globs);
	epp_corba_init_cleanup(corba_globs);

	return 0;
}
