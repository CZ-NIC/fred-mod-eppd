/**
 * @file epp_common.c
 *
 * Function definitions shared by all components of mod_eppd are here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "epp_common.h"

int q_add(void *pool, qhead *head, void *data)
{
	qitem	*item;

	item = epp_malloc(pool, sizeof *item);
	if (item == NULL)
		return 1;

	item->next    = NULL;
	item->content = data;

	if (head->body == NULL) {
		head->body = item;
	}
	else {
		qitem	*iter;

		iter = head->body;
		while (iter->next != NULL)
			iter = iter->next;

		iter->next = item;
	}
	head->count++;
	return 0;
}

