#!/bin/bash

url="http://mayo.example.de/api/v1/user/rpms?base_system=11.1"
echo "ADD RPM $1 via $url"
curl -k -u studio:pass -X POST -H "Content-type: application/x-rpm" -F file=@$1 $url
