#!/usr/bin/perl

package Utils;

use utf8;
use strict;

use Data::Dumper;
use URI;
use URI::Escape;
use LWP;
use LWP::Simple;
use HTTP::Cookies;

use Auth;

our $cookie_jar = undef;
our $ua = undef;
our $res = undef;
our $cookie_jar_file = "$ENV{'HOME'}/.webutils_cookies.dat";

our $cnf_dbg = 0;

sub page_ping($)
{
	my $uri = URI->new(shift);

# 	$cookie_jar = HTTP::Cookies->new(file => $cookie_jar_file, autosave => 1);
	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
# 	$ua->cookie_jar($cookie_jar);
	$ua->cookie_jar($Auth::cookie_jar);

	my $ret = get($uri->as_string);
	unless(defined($ret))
	{
		return 0 unless(head($uri->as_string)); # XXX also try POST
	}

	return 1;
}

sub page_probe($)
{
	my $uri = URI->new(shift);

	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
# 	$ua->cookie_jar($Auth::cookie_jar);

	my $req = HTTP::Request->new(GET => $uri->as_string);

	# build header
	$req->header('Accept'=>"*/*");

	$res = $ua->request($req);

	print "\tDBG: Utils::page_probe -> ", $res->code, "\n" if($cnf_dbg);

	return $res->code;
}

sub page_probe_head($)
{
	my $uri = URI->new(shift);

	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
# 	$ua->cookie_jar($Auth::cookie_jar);

	my $req = HTTP::Request->new(HEAD => $uri->as_string);

	# build header
	$req->header('Accept'=>"*/*");

	$res = $ua->request($req);

	print "\tDBG: Utils::page_probe -> ", $res->code, "\n" if($cnf_dbg);

	return $res->code;
}

sub is_auth_needed($;$)
{
	my $url = shift;
	my $regex = shift;

	my $browser = LWP::UserAgent->new();
	$browser->agent("WEBUTILS/0.1");

	my $req = HTTP::Request->new(GET => $url);
	my $res = $browser->request($req);

# 	print "\nXXX AUTH NEEDED: ", $res->code, "\n";

# 	return 0 if($res->code == 200); # shortcut, no auth needed
	
	# 401 means auth missing
	# 302 means redirect, often to the login page
	if($res->code == 401 or $res->code == 302 or ((defined($regex) and $res->content =~ /$regex/im)))
	{
		return 1;
	}
	return 0;
}

sub forced_browsing($;$) # used to detect unprotected pages behind login, "forced browsing", CWE-425
{
	my $url = shift;
	my $regex = shift;

	my $browser = LWP::UserAgent->new;
	$browser->agent("CWE-425/0.1");
# 	$browser->max_redirect = 0;

	my $req = HTTP::Request->new(GET => $url);
	my $res = $browser->request($req);

# 	return 0 unless(is_auth_needed($url,$regex));

	return 0 if($res->code == 401); # 401 means auth missing
	return 0 if($res->code == 302); # 302 means redirect, often to the login page
	return 0 if(defined($regex) and $res->content =~ /$regex/im);
	return 1; # everything else looks fishy
}

sub head_bypass($;$) # used to detect bypassing authZ with head
{
	my $url = shift;
	my $regex = shift;

	my $browser = LWP::UserAgent->new(max_redirect=>0);
	$browser->agent("CWE-285/0.1");

	my $req = HTTP::Request->new(HEAD => $url);
	my $res = $browser->request($req);

# 	print "XXX HEAD BYPASS: ", $res->code, "\n";

	return 0 if($res->code == 401); # 401 means auth missing
	return 0 if($res->code == 302); # 302 means redirect, often to the login page
	return 0 if(defined($regex) and $res->content =~ /$regex/im);
	return 1; # everything else looks fishy
}

sub csrf_protected($;$;$) # used to detect csrf token
{
	my $url = shift;
	my $form = shift; # XXX hard to get automatically but maybe not needed b/c the token is evaluated first
	my $regex = shift;

	my $res = page_post($url, $form);

	return 1 if($res->code == 500); # internal server error, often returned if csrf token is missing -> rotected
	return 0 if($res->code == 302); # 302 means redirect, often to the login page
	return 1 unless(defined($regex) or $res->content =~ /$regex/im); # redirect to login page -> protected
	return 0; # everything else looks fishy
}

sub page_get($)
{
	my $url = shift;

	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
	$ua->cookie_jar($Auth::cookie_jar);

	my $req = HTTP::Request->new(GET => $url);

	print "\tDBG: Utils::page_get($url)\n" if($cnf_dbg > 1);

	# build header
	$req->header('Accept'=>"*/*");

	$res = $ua->request($req);

	print "\tDBG: Utils::page_get -> ", $res->code, "\n" if($cnf_dbg);

	Auth::auth_find_csrf_token($res); # XXX does it make sense here, likely not

	return $res;
}

sub page_post($;$)
{
	my $url = shift;
 	my $content = uri_escape(shift);
#	my $content = shift;

	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
	$ua->cookie_jar($Auth::cookie_jar);
# 	push $ua->requests_redirectable, 'POST'

	my $req = HTTP::Request->new(POST => $url);

	print "\tDBG: Utils::page_post($url <-- '$content')\n" if($cnf_dbg > 1);

	# build header
	$req->header('Accept'=>"*/*");
	$req->content($content);

	$res = $ua->request($req);

	print "\tDBG: Utils::page_post -> ", $res->code, "\n" if($cnf_dbg);

	return $res;
}

sub page_req($;$)
{
	my $method = shift;
	my $uri = URI->new(shift);

	my $res = undef;
	if($method =~ /POST/i)
	{
		my $url = $uri->as_string;
		my ($page, $c) = split /\?/, $url;
		# add CSRF token
		if(defined($Auth::csrf_token) and (length($Auth::csrf_token) > 0))
		{
 			print "\tDBG: Utils::page_req: adding CSRF token: '$Auth::csrf_token'\n" if($cnf_dbg > 1);
			$c = Auth::auth_add_csrf_token($c);
		}
		$res = page_post($page, $c);
	}
	elsif($method =~ /GET/i)
	{
		$res = page_get($uri->as_string);
	}

	return $res;
}

sub file_probe($)
{
	my $uri = URI->new(shift);

	$ua = LWP::UserAgent->new;
	$ua->agent("WEBUTILS/0.1");
	$ua->cookie_jar($Auth::cookie_jar);

	my $req = HTTP::Request->new(GET => $uri->as_string);

	# build header
	$req->header('Accept'=>"*/*");

	$res = $ua->request($req);

	print "\tDBG: Utils::file_probe -> ", $res->code, "\n" if($cnf_dbg);

	return undef unless($res->code == 200);

	return $res->header('Content-Type');
}

sub hash_merge($;$)
{
	my $h1 = shift;
	my $h2 = shift;
	my %h = ();

	foreach my $k (keys %$h1)
	{
		$h{$k} = $h1->{$k};
	}
	foreach my $k (keys %$h2)
	{
		$h{$k} = $h2->{$k};
	}
	
# 	print Dumper(%h);

	return %h;
}

1;