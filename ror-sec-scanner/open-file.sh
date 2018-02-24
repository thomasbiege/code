#!/bin/bash

while true;do read ans; kwrite $(echo $ans | sed s/:/\ \-\-line\ /);done


