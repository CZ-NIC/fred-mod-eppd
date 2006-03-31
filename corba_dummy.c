#include <string.h>

#include "epp_corba.h"

int corba_login(epp_data_login *login_data) {
	login_data->svTRID = strdup("server-transID");
	login_data->sessionID = strdup("sessionID");
	login_data->rc = 1000;

	return 1;
}
