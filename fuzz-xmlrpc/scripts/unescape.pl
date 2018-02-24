#!/usr/bin/perl

open FD, "< u";
while(<FD>)
{
	chomp;

	if(/>((GET|PUT|POST)\s+.+[\w;])<\//)
	{
		$l = $1;
		$l =~ s/&lt;/</g;
		$l =~ s/&gt;/>/g;
		$l =~ s/&amp;/&/g
		print "$l\n";
	}
}
close FD;

