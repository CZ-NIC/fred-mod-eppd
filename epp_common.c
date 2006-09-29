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

