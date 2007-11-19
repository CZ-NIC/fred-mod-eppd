/*  
 *  Copyright (C) 2007  CZ.NIC, z.s.p.o.
 *
 *  This file is part of FRED.
 *
 *  FRED is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2 of the License.
 *
 *  FRED is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with FRED.  If not, see <http://www.gnu.org/licenses/>.
 */
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

