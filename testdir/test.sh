#!/bin/sh

# localhost
#./epptelnet.pl -s -k client.key -c client.crt epp-s-01.nic.cz 700
# remote host
./epptelnet.pl -s -k client.key -c client.crt epp-test.ccreg.nic.cz 700
