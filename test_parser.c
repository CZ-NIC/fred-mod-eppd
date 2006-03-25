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
			fprintf(stderr, "Maximal allowed cmd lenght exceeded\n");
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

	printf("type text: ");
	while ((c = getchar()) != EOF) {
		text[i++] = (char) c;
		if (i >= MAX_LENGTH - 1) {
			fprintf(stderr, "Maximal allowed text lenght exceeded\n");
			break;
		}
	}
	text[i] = 0;
}

int main(int argc, char *argv[])
{
	char text[MAX_LENGTH];
	char quit = 0;
	void *ctx;
	cmd_t cmd;
	epp_parser_parms_out parser_out;
	epp_status_t status;
	epp_parser_log *log_iter;

	ctx = epp_parser_init();
	while (1) {
		puts("Command: ");
		switch (cmd = getcmd()) {
			case CMD_CUSTOM:
				readinput(text);
				break;
			case CMD_EXIT:
				quit = 1;
				break;
			default:
				puts("Unknown command\n");
				break;
		}
		if (quit) break;

		bzero(&parser_out, sizeof parser_out);
		epp_parser_process_request(ctx, text, &parser_out);

		/* print result */
		puts("\nResults are:");
		printf("Status val is %d\n", parser_out.status);

		log_iter = parser_out.head;
		puts("parser log:\n");
		while (log_iter) {
			printf("severity: %d\n", log_iter->severiry);
			printf("content: %s\n", log_iter->msg);
			log_iter = log_iter->next;
		}

		epp_parser_cleanup_parms_out(&parser_out);
	}
	epp_parser_cleanup(ctx);

	return 0;
}
