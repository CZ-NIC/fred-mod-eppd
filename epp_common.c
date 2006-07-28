/**
 * @file epp_common.c
 * Function definitions shared by all components of mod_eppd are here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "epp_common.h"

inline unsigned cl_length(struct circ_list *cl)
{
	unsigned	i = 0;
	for (cl = cl->next; cl->content != NULL; cl = cl->next) ++i;
	return i;
}

inline void cl_purge(struct circ_list *cl)
{
		struct circ_list	*temp;

		cl = cl->next;
		while (cl->content != NULL) {
			temp = cl->next;
			free(cl);
			cl = temp;
		}
		free(cl);
}

void get_rfc3339_date(long long date, char *str)
{
	struct tm t;
	time_t	time = date;

	/* we will leave empty string in buffer if gmtime failes */
	if (gmtime_r(&time, &t) == NULL) {
		str[0] = '\0';
		return;
	}
	snprintf(str, 25, "%04d-%02d-%02dT%02d:%02d:%02d.0Z",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec);
}

void get_stripped_date(long long date, char *str)
{
	struct tm t;
	time_t	time = date;

	/* we will leave empty string in buffer if gmtime failes */
	if (gmtime_r(&time, &t) == NULL) {
		str[0] = '\0';
		return;
	}
	snprintf(str, 25, "%04d-%02d-%02d",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday);
}

