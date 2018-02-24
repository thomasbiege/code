#!/bin/bash

# usage: add_entries.sh file.xml https://dhcp26.example.de/jobs.xml

echo "MOD $1 to $2"
curl -k -u studio:pass -X PUT -H "Content-type: text/xml" -F new=@$1 $2
