#!/usr/bin/perl

use strict;
use utf8;
use Data::Dumper;
#use File::MimeInfo::Magic;
use File::Basename;
use Cwd qw(realpath);
use Math::Round qw(round);
use Digest::CRC;

BEGIN {
    my $f = $0;
    if($0 =~ /^\//)
    {
	my $i = 10;
	while(-l $f && $i > 0)
	{
	    my $l = readlink $f;
	    if(!($l =~ /^\//))
	    {
		$l = dirname($f).'/'.$l;
	    }
	    $f = $l;
	    --$i;
	}
	if (!$i)
	{
	    print STDERR "too many symbolic links\n";
	    exit 1;
	}
	unshift @INC, dirname($f);
    }
    push @INC, sprintf("%s/lib", $ENV{PWD});
}


our $cnf_from	= undef;
our $cnf_to	= undef;
our $cnf_n	= 0;
our @f = ();

#
# SUB
# 
sub crc32file($)
{
	my $f = shift;
	open(SOMEFILE, $f);
	my $ctx = Digest::CRC->new(type=>"crc32");
	$ctx->addfile(*SOMEFILE);
	my $crc = $ctx->hexdigest;
	close(SOMEFILE);
	return $crc;
}

sub crc32cmp($;$)
{
	my $file1 = shift;
	my $file2 = shift;

	my $chksum1 = crc32file($file1);
	my $chksum2 = crc32file($file2);

	return 1 unless($chksum1 eq $chksum2);
	return 0;
}

sub mycmp($;$)
{
	my $f = shift;
	my $t = shift;

	my $nfiles = scalar @f;
	my $iter = round($nfiles * ($cnf_n/100));

	print "nfiles = $nfiles\n";
	print "iter = $iter\n";
	
	while($iter)
	{
		$iter--;
		my $rnd = rand($nfiles-1);
		my $fn = $f[$rnd];
		unless(-f "$t/$fn")
		{
			print "file '$t/$fn' does not exist.\n";
			next;
		}
		if(crc32cmp("$f/$fn", "$t/$fn") != 0)
		{
			print "file '$fn' does not match.\n";
		}
	}
}

#
# MAIN
#
foreach(@ARGV)
{
	$cnf_from	= $1	if(/from=(.*)/);
	$cnf_to		= $1	if(/to=(.*)/);
	$cnf_n		= $1	if(/n=(\d+)%/);
	if(/help/i)
	{
		print "cc.pl n=<x% to check> from=<dir> to=<dir>\n";
		exit 0;
	}
}
unless(defined($cnf_from) or defined($cnf_to))
{
	print "cc.pl n=<% files to check> from=<dir> to=<dir>\n";
	exit 0;
}
if($cnf_n <= 0)
{
	print "n must be > 0\n";
	exit 0;
}

print "from=$cnf_from\nto=$cnf_to\nn=$cnf_n%\n";

foreach my $file (`find $cnf_from/ -type f -print`)
{
	$file =~ s/^$cnf_from//;
	$file =~ s/^\///;
	chomp $file;
	push @f, $file;
}

mycmp($cnf_from, $cnf_to);


0;
