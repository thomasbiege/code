#!/usr/bin/perl

# author: Thomas Biege <tom@electric-sheep.org>
# last update: 2011-11-08
# example: ./xssfuzz.pl fuzz_file=fuzzdb-read-only/attack-payloads/xss/xss-rsnake.txt https://www.exaple.com:443/ruby?proj=FUZZ

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
}

use strict;
use utf8;
use Data::Dumper;
use LWP::UserAgent;
use HTTP::Request::Common;
use URI::Escape;
use Thread;

$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

use Auth;


#
# MAIN
#
our $cnf_user		= "";
our $cnf_pass		= "";
our $cnf_cred		= "";
our $cnf_login		= undef;
our $cnf_scheme		= "https://";
our $cnf_host		= "example.org:443";
our $cnf_path		= "/show?proj=FUZZ";
our $cnf_target		= $cnf_scheme.$cnf_host.$cnf_path;
our $cnf_threaded	= 0;
our $cnf_sleep		= 0;
our $cnf_log_debug	= 0;
our $cnf_log_http	= 0;
our $cnf_fuzz_file	= "";
our $cnf_fuzz_idx	= 0;
our $cnf_cookie		= "";
our $cnf_csrf_token_name  = "authenticity_token";
our $cnf_csrf_token_regex = "name=\"authenticity_token\".*value=\"([A-Za-z0-9\/=\+]*)\"";

foreach(@ARGV)
{
	$cnf_log_debug	= 1 if(/log=debug/i);	# just more info
	$cnf_log_http	= 1 if(/log=http/i);	# just more info
	$cnf_threaded	= 1 if(/threaded/i);

	$cnf_cookie	= $1 if(/cookie=(.*)/);
	$cnf_sleep	= $1 if(/sleep=(.*)/);

	# form auth credentials
	if(/auth_basic=(.*):(.*)/)
	{
		$cnf_user = $1;
		$cnf_pass = $2;
		$cnf_login = $3;
	}

	if(/auth_post=(.*)@(.*)/)
	{
		$cnf_cred = $1;
		$cnf_login = $2;
	}

	# target host to test
# 	if(/(http[s]*:\/\/)([\w\d\-_\.:]+)\/([\/\d\w\.\?\&]*)/i)
# 	{
# 		$cnf_scheme = $1;
# 		$cnf_host = $2;
# 		$cnf_path = $3 if(defined($3));
# 	}
	$cnf_target = $1 if(/(http[s]*:\/\/.*)/i);

	# fuzz
	$cnf_fuzz_idx  = $1 if(/fuzz_idx=([\d]+)/);
	$cnf_fuzz_file = $1 if(/fuzz_file=(.*)/);

	if(/help/i)
	{
		print("usage:\t[help]\n\t[log=[debug|http]] [threaded]\n\t[fuzz_file=<payload file>] [fuzz_idx=<start>]\n\t[cookie=<cookie value>] [auth_basic=<user>:<pass>] [auth_post=<post form>@<login page>]\n\t[http[s]]://target.com/path\n");
		exit 0;
	}
}
# $cnf_target = $cnf_scheme.$cnf_host.$cnf_path;

die("specify fuzz payload file") unless length($cnf_fuzz_file);
die("fuzz file '$cnf_fuzz_file' does not exist") if not -f $cnf_fuzz_file;
die("URL needs FUZZ keyword") unless($cnf_target =~ /FUZZ/);

# print config
print
"Config:
\tuser        : $cnf_user
\tpassword    : $cnf_pass
\tpost form   : $cnf_cred
\tlogin at    : $cnf_login
\tfuzz file   : $cnf_fuzz_file
\tfuzz idx    : $cnf_fuzz_idx
\tcookie      : $cnf_cookie
\tthreaded    : $cnf_threaded
\tsleep       : $cnf_sleep
\ttarget      : $cnf_target\n\n";

if(defined($cnf_loign)
{
	Auth::init();
	$Auth::cookie_jar->clear;
	$Auth::cookie_jar->clear_temporary_cookies;
	$Auth::csrf_token = undef; # Auth will do it autom. then
	$Auth::csrf_token_name = $cnf_csrf_token_name;
	$Auth::csrf_token_regex = $cnf_csrf_token_regex;
	$Auth::csrf_uri = $cnf_loign;

	my $cookie = Auth::auth_post($cnf_login, $cnf_cred, "");
	unless(defined($cookie))
	{
		$retval{MSG}  = "INFO: Unable to login ($cnf_uri_login)";
		$retval{CODE} = -2;
		goto RET;
	}
	if($cnf_log_debug)
	{
		print "\tDBG: $retval{TESTNAME} cookie = '", join(",", Auth::split_cookie($cookie)), "'\n";
	}
}

fuzz();

Auth::deinit() if(defined($cnf_login));

print "\ndone\n";

0;

#
# SUBS
#

sub fuzz()
{
	my $tmphn = $cnf_target;
	$tmphn =~ s/http[s]*:\/\///g;
	$tmphn =~ s/\//_/g;
	$tmphn =~ s/\?/_/g;
	$tmphn =~ s/\&/_/g;
	$tmphn =~ s//_/g;
	$tmphn =~ s/__/_/g;
	open FD, ">> xssfuzz_$tmphn.txt" or return 1;
	FD->autoflush(1);

	open FD_FUZZ, "< $cnf_fuzz_file" or die("unable to open fuzz file '$cnf_fuzz_file'");

	my $thr_ret = 1;
# 	my $file_size = -s $cnf_fuzz_file;
	while(<FD_FUZZ>)
	{
		next if(/^#.*/);
		chomp;
		my $fuzz_word = $_;
		$fuzz_word = uri_escape($fuzz_word);

		print "." unless($cnf_log_debug or $cnf_log_http);

		my $t = $cnf_target;
		$t =~ s/FUZZ/$fuzz_word/g;

		if($cnf_threaded) # XXX this does not really work, $thr->join to verify @rc
		{
			$thr_ret = new Thread \&http_request, $t;
			unless(defined($thr_ret))
			{
				sleep($cnf_sleep);
				next;
			}
			$thr_ret->detach();
		}
		else
		{
			my $fuzz_ok = 1;
			my @rc = http_request($t);
# 			print $rc[2];
			foreach my $line (@rc[2])
			{
# 				print "line: ", $line;
				chomp $line;
				my $pos = index $line, $fuzz_word;
				next if($pos < 0);
				print "FOUND '$fuzz_word' in line '$line'";
				$fuzz_ok = 0;

			}
			if($cnf_log_debug or not $fuzz_ok)
			{
				print "$t: '$rc[1]' -> ", $fuzz_ok ? "ok" : "SUSPICIOUS" ,"\n";
			}
			print FD "$t: '$rc[1]'\n" unless($fuzz_ok);
		}
		sleep($cnf_sleep);
	}
	close(FD);
	close(FD_FUZZ);
	return 0;
}

sub http_request($)
{
	return http_request_get(shift);
}

sub http_request_get($)
{
	my $uri = shift;

	# User Agent
	my $ua = LWP::UserAgent->new();
	$ua->agent("XSSFUZZ/0.1 ");

	print "http request: GET $uri\n" if($cnf_log_http);

	# Create a request
	my $req = HTTP::Request->new(GET => $uri);

	# build header
	$req->header('Accept'=>"*/*");
	$req->header('Host'=>$cnf_host);
	if(length($cnf_user) and length($cnf_pass))
	{
		$req->header('Authorization'=>"Basic ".encode_base64($cnf_user.":".$cnf_pass));
	}
	if(length($cnf_cookie))
	{
		$req->header('Cookie'=>$cnf_cookie);
		$req->header('Cookie2'=>'$Version=1');
	}

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);

	if($res->code == 302) # HTTP redirect
	{
		$uri = $res->header('Location');
		print "HTTP redirect to: $uri" if($cnf_log_http);

		# Create a request XXX better recrusive hal to http_request()
		$req = HTTP::Request->new(GET => $uri);

		# build header
		$req->header('Accept'=>"*/*");
		$req->header('Host'=>$cnf_host);
		if(length($cnf_user) and length($cnf_pass))
		{
			$req->header('Authorization'=>"Basic ".encode_base64($cnf_user.":".$cnf_pass));
		}
		if(length($cnf_cookie))
		{
			$req->header('Cookie'=>$cnf_cookie);
			$req->header('Cookie2'=>'$Version=1');
		}

		# Pass request to the user agent and get a response back
		$res = $ua->request($req);
	}

	print "\n--------------\n", $res->as_string, "\n--------------\n" if($cnf_log_debug and $cnf_log_http);

	# Check the outcome of the response
	return ($res->code, $res->status_line, $res->content);
}

