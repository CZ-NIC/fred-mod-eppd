#!/bin/sh
#
# First argument is schema name with version stripped
# second argument is new version of that schema
#

for schema in `ls *.xml`
do
	sed --in-place -r "s/$1-[0-9]\.[0-9]/$1-$2/" $schema
done
