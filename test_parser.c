#include <stdio.h>
#include <string.h>

#include "epp_parser.h"

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
	char filename[20];
	FILE *f;

	fputs("type filename: ", stderr);
	for (i = 0; (c = getchar()) != '\n' && i < 19; i++) {
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

int main(int argc, char *argv[])
{
	char text[MAX_LENGTH];
	char quit = 0;
	cmd_t cmd;
	epp_command_parms_out command_parms;
	epp_greeting_parms_out greeting_parms;
	void *conn_ctx;
	epp_parser_log *log_iter;

	/* API: check libxml */
	if (!epp_parser_init("schemas/all-1.0.xsd")) {
		fputs("Error in parser initialization\n", stderr);
		return 1;
	}

	/* API: greeting */
	bzero(&greeting_parms, sizeof greeting_parms);
	epp_parser_greeting("Server ID", "curent:date", &greeting_parms);
	if (greeting_parms.error_msg) {
		fprintf(stderr, "Greeting error: %s\n", greeting_parms.error_msg);
	}
	else {
		puts(greeting_parms.greeting);
	}
	/* API: free greeting data */
	epp_parser_greeting_cleanup(&greeting_parms);

	/* API: get connection context */
	conn_ctx = epp_parser_connection();

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

		bzero(&command_parms, sizeof command_parms);
		/* API: process command */
		epp_parser_command(conn_ctx, text, &command_parms);

		fputs("\nResults are:", stderr);
		fprintf(stderr, "Status val is %d\n", command_parms.status);

		log_iter = command_parms.head;
		fputs("parser log:", stderr);
		while (log_iter) {
			fprintf(stderr, "severity: %d\n", log_iter->severity);
			fprintf(stderr, "content: %s\n", log_iter->msg);
			log_iter = log_iter->next;
		}

		if (command_parms.response != NULL)
			puts(command_parms.response);

		/* API: clean up command data */
		epp_parser_command_cleanup(&command_parms);
	}

	/* API: clean up connection data */
	epp_parser_connection_cleanup(conn_ctx);
	epp_parser_init_cleanup();

	return 0;
}
