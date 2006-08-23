#!/bin/sh

NUM=1000

while true
do
NUM=`expr $NUM + 1`
echo $NUM
cat create.xml | sed -e "s/HANDLE/EPP$NUM/" > create$NUM.xml
cat delete.xml | sed -e "s/HANDLE/EPP$NUM/" > delete$NUM.xml
done
