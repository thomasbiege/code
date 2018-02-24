#!/usr/bin/perl -w 
use URI::Escape;

$fn = shift @ARGV;
open FD, $fn or die "unabel to open $fn";
while(<FD>)
{
	print uri_unescape($_);
}
close FD

