#!/bin/bash

if [ -z $1 ]
then
	echo "filename missing"
	exit
fi

echo "char *pl[] = "
echo "{"

for i in `cat $1`
do
	j=`echo $i | sed 's#\"#\\\\\"#g'`
	i=`echo $j | sed 's#\+#\]#g'`
	j=`echo $i | sed 's#\/#\&#g'`
	echo "  \"$j\","
	echo -n "." >&2
done

echo "   false"
echo "};"


