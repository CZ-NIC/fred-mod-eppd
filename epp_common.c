#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "epp_common.h"

/* count the number of items in the list */
inline unsigned cl_length(struct circ_list *cl)
{
	unsigned	i = 0;
	for (cl = cl->next; cl->content != NULL; cl = cl->next) ++i;
	return i;
}

/*
 * purge circular list, note that all content must be freed upon using
 * this inline. List pointer must be at the beginning upon start.
 */
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

/**
 * Function for converting number of seconds from 1970 ... to string
 * formated in rfc 3339 way. This is required by EPP protocol.
 * @par date Number of seconds since ...
 * @par str buffer allocated for date (should be at least 25 bytes long)
 */
void get_rfc3339_date(long long date, char *str)
{
	struct tm t;
	time_t	time = date;

	/* we will leave empty buffer if gmtime failes */
	if (gmtime_r(&time, &t) == NULL) {
		str[0] = '\0';
		return;
	}
	snprintf(str, 25, "%04d-%02d-%02dT%02d:%02d:%02d.0Z",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec);
}

/**
 * Same as above but only the date portion is returned. The time
 * is omitted.
 * @par date Number of seconds since ...
 * @par str buffer allocated for date (should be at least 11 bytes long)
 */
void get_stripped_date(long long date, char *str)
{
	struct tm t;
	time_t	time = date;

	/* we will leave empty buffer if gmtime failes */
	if (gmtime_r(&time, &t) == NULL) {
		str[0] = '\0';
		return;
	}
	snprintf(str, 25, "%04d-%02d-%02d",
			1900 + t.tm_year, t.tm_mon + 1, t.tm_mday);
}

