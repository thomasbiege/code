#!/usr/bin/perl -w

use strict;
use utf8;

use File::Fetch;
use Config::Simple;
use Data::Dumper;
use POSIX;

BEGIN {
if($0 =~ /^\//)
{
	my $f = $0;
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
}

use Auth;
use Utils;
use Spider;
use ParsePage;
use SPIDB;

our $cnf_depth = 2;
our $cnf_login_url = undef;
our $cnf_login_method = undef;
our $cnf_login_cred = undef;
our $cnf_login_regex = undef;
our $cnf_spider_url = undef;
our @cnf_ignore_url = ();
our $cnf_cookie_name = undef;
our $cnf_chk_head_bypass = undef;
our $cnf_chk_csrf_prot = undef;
our $cnf_dbg = 0;
our $cnf_csrf_token_name = undef;
our $cnf_csrf_token_regex = undef;
our $cnf_csrf_uri = undef;

our $cnf_sw_parse = 1;
our $cnf_sw_public = 0;


$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

sub parse_webpage($)
{
	my $url_href = shift;

	my $s = 0;

	# parse page individually if possible
	ParsePage::init($Auth::cookie_jar_file);
	ParsePage::parse_url($_) foreach (keys %$url_href);
	$s = ParsePage::bytes_downloaded();
	ParsePage::cleanup();
	ParsePage::deinit();

	return $s;
}


sub process_webpages_file($)
{
	my $fname = shift;

	my $time_spider_start = 0;
	my $time_spider_diff = 0;
	my $time_parse_start = 0;
	my $time_parse_diff = 0;
	my $s = 0;
	my $url_cnt = 0;


	#
	# config file
	print "reading config file '$fname'\n";
	my $cfg = new Config::Simple($fname);
	my %cfgh = Utils::hash_merge($cfg->param(-block=>'DEFAULT'), $cfg->param(-block=>'CHECK'));

	foreach my $key (keys %cfgh)
	{
		$cnf_dbg              = $cfgh{$key} if($key eq 'dbg');
		$cnf_depth            = $cfgh{$key} if($key eq 'depth');
		$cnf_login_url        = $cfgh{$key} if($key eq 'login_url');
		$cnf_login_method     = $cfgh{$key} if($key eq 'login_method');
		$cnf_login_cred       = $cfgh{$key} if($key eq 'login_cred');
		$cnf_login_regex      = $cfgh{$key} if($key eq 'logout_regex');
		$cnf_spider_url       = $cfgh{$key} if($key eq 'spider_url');
		$cnf_cookie_name      = $cfgh{$key} if($key eq 'cookie_name');
		$cnf_chk_head_bypass  = $cfgh{$key} if($key eq 'head_bypass');
		$cnf_chk_csrf_prot    = $cfgh{$key} if($key eq 'csrf_prot');

		$cnf_csrf_token_name  = $cfgh{$key} if($key eq 'csrf_token_name');
		$cnf_csrf_token_regex = $cfgh{$key} if($key eq 'csrf_token_regex');
		$cnf_csrf_uri         = $cfgh{$key} if($key eq 'csrf_url');

		if($key eq 'ignore_url')
		{
			push @cnf_ignore_url, $_ foreach (@{$cfgh{$key}});
		}
	}

	unless(	defined($cnf_login_url) and
		defined($cnf_login_method) and
		defined($cnf_login_cred) and
		defined($cnf_spider_url))
	{
		die("error: some important config options are missing in '$fname'\n");
	}

	$cnf_csrf_uri = $cnf_login_url unless(defined($cnf_csrf_uri));

	#
	# print config
	print "depth = $cnf_depth, spider url = $cnf_spider_url, login url = $cnf_login_url, csrf url = $cnf_csrf_uri\n";
	print "ignore url:\n";
	print "\t$_\n" foreach (@cnf_ignore_url);
	my $target = undef;
	$target = $1 if($cnf_spider_url =~ /http[s]*:\/\/([\w\d\-_\.]+)/);
	next unless defined $target;
	print "target: $target\n";

	mkdir $target;
	chdir $target;

	#
	# spider
	print "\tspider at $cnf_spider_url with depth $cnf_depth\n";
	Spider::init();
	$Spider::cnf_login_url = $cnf_login_url;
	$Spider::cnf_login_method = $cnf_login_method;
	$Spider::cnf_login_cred = $cnf_login_cred;
	$Spider::cnf_login_regex = $cnf_login_regex;
	$Spider::cnf_cookie_name = $cnf_cookie_name;
	$Spider::cnf_csrf_token_name = $cnf_csrf_token_name;
	$Spider::cnf_csrf_token_regex = $cnf_csrf_token_regex;
	$Spider::cnf_csrf_uri = $cnf_csrf_uri;
	@Spider::cnf_ignore_url = @cnf_ignore_url;


	print "\tspider authenticate\n";
	my $cookie = Spider::auth();
	die("\tauthentication failed\n") unless(defined($cookie));

	$time_spider_start = time();
	my $spidb = {};
	my (@url_ok, @url_exit) = Spider::spider_deep($cnf_spider_url, $cnf_depth, $spidb);
	$time_spider_diff = time() - $time_spider_start;

	$url_cnt = scalar keys %$spidb;
	print "\t\t$target: found $url_cnt URLs of depth $cnf_depth in $time_spider_diff secs\n";

	#
	# DB
	SPIDB::init($target.".db");
	print "\twrite spider output to database: ", $SPIDB::fn, "\n";
	SPIDB::write_all($spidb);
	SPIDB::deinit();

	#
	# parse page
	if($cnf_sw_parse)
	{
		print "\tparsing found html pages:\n";
		$time_parse_start = time();
		$s = parse_webpage($spidb); # XXX not really needed for spidering, just information ripping
		$time_parse_diff = time() - $time_parse_start;
		$time_parse_diff = 1 if($time_parse_diff <= 0);

		printf("\n\t%s: parsed %d URLs [%d bytes] in %d secs with %.2f bytes/sec\n",
			$target, $url_cnt, $s, $time_parse_diff, $s/$time_parse_diff);
	}

	chdir "..";

	return ($time_spider_diff, $time_parse_diff, $url_cnt, $s);
}

#
# MAIN
#
umask(077);

our $cnf_file = "web-pages.ini";

foreach(@ARGV)
{
	$cnf_file = $1 if(/([\w\d\-\_\.\:]+\.ini)/);	# config file

	$cnf_sw_parse =  0 if /noparse/; # do not parse pages
	$cnf_sw_public = 1 if /public/;  # just public pages
}
my $time_start = time();
my ($s, $p, $c, $z) = process_webpages_file($cnf_file);
my $time_diff = time() - $time_start;
# div by zero ctaching
$time_diff = 1 if($time_diff <= 0);
$s = 1 if($s <= 0);
$p = 1 if($p <= 0);

print "\n\nBenchmark:\n";
printf "\ttotal  time:  %d secs\n", $time_diff;
printf "\tspider time:  %d secs\n", $s;
printf "\tspider ratio: %.2f URLs/sec\n", $c/$s;
printf "\tparse  time:  %d secs\n", $p;
printf "\tparse  ratio: %.2f bytes/sec\n\n", $z/$p;


0;

