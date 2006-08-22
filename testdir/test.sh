#!/bin/sh

# localhost
./epptelnet.pl -s -k client.key -c client.crt localhost 8700
# remote host
#./epptelnet.pl -s -k client.key -c client.crt curlew 700
