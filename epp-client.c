#include <string.h>

#include "epp-client.h"

int corba_login(epp_data_login *login_data) {
	login_data->svTRID = strdup("server-transID");
	login_data->sessionID = 1010;
	login_data->rc = 1000;

	return 1;
}
