#include <stdlib.h>

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
