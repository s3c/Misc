#!/bin/bash

for ip in `cat $1`
do
    curlresponse=`curl -m 5 -x $ip google.com 2> /dev/null`
    googlepresent=`echo $curlresponse | grep google.com`
    if [ -n "$googlepresent" ]; then
        echo -e "\e[00;32mActive: $ip \e[00m"
        echo $ip >> proxylist_active.txt
    else
        echo -e "\e[00;31mInactive: $ip \e[00m"
    fi
done
