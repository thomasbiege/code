#!/bin/bash

url="http://mayo.example.de/api/v1/user/rpms/3"
echo "MOD RPM $1 via $url"
curl -k -u studio:pass -X PUT -H "Content-type: application/x-rpm" -F file=@$1 $url
