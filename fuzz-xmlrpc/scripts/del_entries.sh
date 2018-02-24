#!/bin/bash

# usage: del_entries.sh https://dhcp26.example.de/customers/INC.xml 2 1000
#    or: del_entries.sh http://mayo.example.de/api/v1/user/appliances/INC 16 188
url=$1
for ((i=$2;i<=$3;i++))
do
	newurl=$(echo ${url} | sed s/INC/${i}/g)
	echo "DELETE $newurl"
	curl -k -u studio:pass -X DELETE $newurl 2>&1>/dev/null
done
