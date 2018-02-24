#!/usr/bin/perl -w

# sqlite example: http://souptonuts.sourceforge.net/code/perlExample.pl.html

package SPIDB;

use strict;
use DBI qw(:sql_types);
use Data::Dumper;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use URI::URL;
use URI::Escape;

my  $init = 0;
our $fn = "spider.db";
our $sql_dbh = undef;
our $sql_pre_ins = undef;
our $sql_pre_del = undef;


sub init($)
{
	if(defined($sql_dbh))
	{
		print "ERROR: DB: you called init twice, call deinit first\n";
		return 0;
	}

	$fn = shift;

	attach();

	unless(-f $fn) # create a new db
	{
# 		print "DB::init: db file does not exist, create table\n";
		create_table();
	}
	if(-f $fn and -s $fn == 0) # create a new db
	{
# 		print "DB::init: db file exist but is empty, create table\n";
		create_table();
	}

	$sql_pre_ins = $sql_dbh->prepare("INSERT INTO url VALUES (?,?,?,?,?,?,?,?,?,?)");
	$sql_pre_del = $sql_dbh->prepare("DELETE FROM url WHERE key = ?");

	$init = 1;
}

sub deinit()
{
	return 1 unless(defined($sql_dbh));

	$sql_dbh->disconnect;
	$sql_dbh = undef;
	$sql_pre_ins = undef;
	$init = 0;
}

sub create_table()
{
	return 1 unless(defined($sql_dbh));

	$sql_dbh->do( "CREATE TABLE url (
		key		VARCHAR(33) NOT NULL,
		uri		TEXT,
		scheme		TEXT,
		path		TEXT,
		params		TEXT,
		forced_browsing	INTEGER,
		head_bypass	INTEGER,
		fuzzable	INTEGER,
		csrf_protected	INTEGER,
		date		DATE,
		PRIMARY KEY(key))");

	return 0;
}


sub attach()
{
	$sql_dbh = DBI->connect( "dbi:SQLite:dbname=".$fn, "", "") || die "Cannot connect: $DBI::errstr";
	return 0;
}


sub write_record($;$)
{
	my $uri = URI->new(shift);
	my $db = shift;
	my @bind_values = ();

	return 1 unless(defined($sql_dbh));
	return 1 unless(defined($sql_pre_ins));
	return 1 unless(defined($uri));

	$bind_values[0]  = create_key($uri->as_string, $db->{'date'});

	# XXX dirty hack for doing updates
	$sql_pre_del->execute(@bind_values) or print "DBG: execute del: ", $DBI::errstr, "\n";


	$bind_values[1]  = $uri->as_string;
	$bind_values[2]  = $uri->scheme;
	$bind_values[3]  = $uri->path;
	$bind_values[4]  = "";
	$bind_values[4]  = $1 if($uri->as_string =~/(\?.*)/);
	$bind_values[5]  = $db->{'forced_browsing'};
	$bind_values[6]  = $db->{'head_bypass'};
	$bind_values[7]  = $db->{'fuzzable'};
	$bind_values[8]  = $db->{'csrf_protected'};
	$bind_values[9]  = $db->{'date'};

	$sql_pre_ins->execute(@bind_values) or print "DBG: execute ins: ", $DBI::errstr, "\n";

	return 0;
}

sub write_all($)
{
	my $spidb = shift;

	foreach my $uri (keys %$spidb)
	{
# 		print "DEBUG: $uri: ", Dumper($spidb->{$uri}) , "\n";
		write_record($uri, $spidb->{$uri});
	}
}

#
# utils
sub create_key($;$)
{
	my $uri = shift;
	my $date = shift;
# 	return md5_hex(uri_escape_utf8($uri)."$date");
	return md5_hex(uri_escape_utf8($uri));
}

#
# statistics
sub stat_avg(@)
{
	my @a = @_;
	return 0 unless(defined($a[0]));
	return 0 unless $#a;
	my $sum = 0;
	foreach my $e (@a)
	{
		$sum = $sum + $e;
	}
	return $sum / ($#a+1);
}

sub stat_stddev(@)
{
	my @a = @_;
	my $avg = stat_avg(@a);
	return 0 unless($avg);

	my $sum = 0;
	foreach my $e (@a)
	{
		$sum = $sum + (($e - $avg)**2);
	}
	my $variance = $sum / ($#a+1);
	return sqrt $variance;
}

sub stat_min(@)
{
	my @a = @_;
	return 0 unless(defined($a[0]));
	return 0 unless $#a;
	return $a[0];
}

sub stat_max(@)
{
	my @a = @_;
	return 0 unless(defined($a[0]));
	return 0 unless $#a;
	return 0 unless(defined($a[$#a]));
	return $a[$#a];
}

sub stat_median(@)
{
	my @a = @_;
	return 0 unless(defined($a[0]));
	return 0 unless $#a;
	my $median = 0;

	# XXX handle arrays with size 1

	my $sz = $#a+1;
	if($sz % 2) # uneven num of elements
	{
		my $off = sprintf "%i", ($sz / 2);
		$median = $a[$off];
	}
	else
	{
		my $off1 = sprintf "%i", ($sz / 2);
		return 0 unless($off1);
		my $off2 = $off1+1;
		return 0 unless(defined($a[$off1]));
		return 0 unless(defined($a[$off2]));
		$median = ($a[$off1] + $a[$off2]) / 2;
	}

	return $median;
}

sub stat_devide_array(@)
{
	my @a = @_;
	return (undef, undef) unless(defined($a[0]));
	return (undef, undef) unless $#a;
	my (@a1, @a2);

	# XXX handle arrays with size 1

	my $sz = $#a+1;
	my $off = sprintf "%i", ($sz / 2); # rounding
	$off-- unless($sz % 2); # even num of elements
	@a1 = @a[0..$off];
	$off++;
	@a2 = @a[$off..$#a];
	return \@a1, \@a2;
}

sub stat_quartile_analysis(@)
{
	my @a = @_;
	return (undef, undef, undef, undef) unless(defined($a[0]));
	return (undef, undef, undef, undef) unless $#a;
	my ($q1, $q2, $q3, $q4);

	($q1, $q3) = stat_devide_array(@a);
	($q1, $q2) = stat_devide_array(@$q1);
	($q3, $q4) = stat_devide_array(@$q3);

	return ($q1, $q2, $q3, $q4);
}

sub stat_quartile_summary(@)
{
	my @a = @_;
	return (0,0,0,0) unless(defined($a[0]));
	return (0,0,0,0) unless $#a;
	my ($q1, $q2, $q3, $q4) = stat_quartile_analysis(@a);
	$q1 = stat_avg(@$q1);
	$q2 = stat_avg(@$q2);
	$q3 = stat_avg(@$q3);
	$q4 = stat_avg(@$q4);
	return $q1, $q2, $q3, $q4;
}


1;
