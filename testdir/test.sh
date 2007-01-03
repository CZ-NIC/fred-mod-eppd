#!/bin/sh

# localhost
#./epptelnet.pl -s -k client.key -c client.crt localhost 8700
# remote hosts
#./epptelnet.pl -s -k client.key -c client.crt curlew 700
./epptelnet.pl -s -k client.key -c client.crt andromeda 700
#./epptelnet.pl -s -k production.key -c production.crt andromeda 700
