#!/usr/bin/perl
use strict;
use utf8;

package Auth;

use LWP;
use LWP::Simple;
use Data::Dumper;
use HTTP::Cookies;
use URI::URL;
use URI::Escape;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use POSIX;

our $cookie_jar = undef;
our $ua = undef;
our $res = undef;
our $cnf_cookie_enable = 1;
our $cnf_auth_regex = undef;
our $cnf_dbg = 0;

our $cookie_jar_file = "$ENV{'HOME'}/.webauth_cookies.dat";
our $csrf_token = undef;
our $csrf_token_regex = undef;
our $csrf_token_name = undef;
our $csrf_uri  = undef;

sub init()
{
	$cookie_jar = HTTP::Cookies->new(file => $cookie_jar_file, autosave => 1, ignore_discard => 1);
	$ua = LWP::UserAgent->new;
	$ua->agent("WEBAUTH/0.1");
	$ua->cookie_jar($cookie_jar);
}

sub deinit()
{
	$cookie_jar->clear;
	$cookie_jar->clear_temporary_cookies;
	$cnf_auth_regex = undef;
	$cookie_jar = undef;
	$ua = undef;
	$csrf_token = undef;
	$csrf_token_regex = undef;
	$csrf_token_name = undef;
}

sub auth_get_csrf_token($)
{
	my $url = shift;
	my $c = undef;
	my $req = HTTP::Request->new(GET => $url);

	$res = $ua->request($req);

	# check if e were successful
	print "\tDBG: Auth::auth_get_csrf_token: [$url] HTTP code: ", $res->code, " (", $res->message, ")\n" if($cnf_dbg);

	return undef if($res->code >= 400);
	return auth_find_csrf_token($res);
}

sub auth_find_csrf_token($)
{
	my $res = shift;

	my $c = undef;
	# find a CSRF protection token
	if(defined($csrf_token_regex) and defined($csrf_token_name))
	{
		if($res->as_string =~ /$csrf_token_regex/i)
		{
			$c = "$csrf_token_name"."="."$1";
			print "\tDBG: Auth::auth_find_csrf_token: found CSRF token: $c\n" if($cnf_dbg);
		}
	}
	$csrf_token = $c if(defined($c) and length($c) > 0); # really only overwrite it if we found a CSRF token
	return $csrf_token;
}

sub auth_add_csrf_token($)
{
	my $astr = shift;
	return $astr unless(defined($csrf_token));
	return sprintf("%s&%s", uri_escape($csrf_token), $astr);
	#return $csrf_token."&".$astr;
}

sub auth_post($;$;$)
{
	return undef unless(defined($ua));

	my $url = shift;
	my $auth_string = shift;
	my $regex = shift;

	# maybe the caller already set the csrf_token, then we should not try to get it
	auth_get_csrf_token($csrf_uri) unless(defined($csrf_token));

	my $req = HTTP::Request->new(POST => $url);

	# build header
# 	my $h = $cnf_host;
# 	$h =~ s/:\d+//;
	$req->header('Accept'=>"*/*");
# 	$req->header('Host'=>$h);
# 	$req->header('Referer'=>$cnf_scheme.$cnf_host."/rhn/");
# 	$req->header('Connection'=>"Keep-Alive, TE");
#
	if(defined($auth_string))
	{
		$auth_string = auth_add_csrf_token($auth_string);
		$req->header('Content-length'=>length($auth_string));
		$req->content_type("application/x-www-form-urlencoded");
		$req->content($auth_string);
	}

	$res = $ua->request($req);

#  	print "INTERROR:", Dumper($res), "\n" if($res->code == 500 && $cnf_dbg);

	# check if we were successful
	print "\tAuth::auth_post: HTTP code: ", $res->code, " (", $res->message, ")\n" if($cnf_dbg);

	return undef if($res->code >= 400);
	if(defined($regex) and length($regex))
	{
# 		print "DEBUG: test regex\n";
		return undef if($res->as_string =~ /$regex/);
	}

	$cookie_jar->save;
	my $c = $res->header('Set-Cookie');
	return undef if(not defined($c) or length($c) == 0);
# 	print "DEBUG: cookie :", $c, "\n";

	# maybe we received a new CSRF token
	auth_find_csrf_token($res);

	return $c;
}

sub auth_post_with_cookie($;$;$;$)
{
	return undef unless(defined($ua));

	my $url = shift;
	my $auth_string = shift;
	my $regex = shift;
	my $cookie = shift;

	# maybe the caller already set the csrf_token, then we should not try to get it
	auth_get_csrf_token($csrf_uri) unless(defined($csrf_token));

	my $req = HTTP::Request->new(POST => $url);

	# build header
# 	my $h = $cnf_host;
# 	$h =~ s/:\d+//;
	$req->header('Accept'=>"*/*");
# 	$req->header('Host'=>$h);
# 	$req->header('Referer'=>$cnf_scheme.$cnf_host."/rhn/");
	$req->header('Connection'=>"Keep-Alive, TE");
# 	$req->header('Cookie'=>$cookie); will be done by cookie jar
	if(defined($auth_string))
	{
		$auth_string = auth_add_csrf_token($auth_string);
		$req->header('Content-length'=>length($auth_string));
		$req->content_type("application/x-www-form-urlencoded");
		$req->content($auth_string);
	}

	$res = $ua->request($req);

	# check if e were successful
	print "\tAuth::auth_post_with_cookie: HTTP code: ", $res->code, " (", $res->message, ")\n" if($cnf_dbg);

# 	print Dumper($res);

	return undef if($res->code >= 400);
	if(defined($regex) and length($regex))
	{
# 		print "DEBUG: test regex\n";
		return undef if($res->as_string =~ /$regex/);
	}

	$cookie_jar->save;
	my $c = $res->header('Set-Cookie');
	return undef if(not defined($c) or length($c) == 0);
# 	print "DEBUG: cookie :", $c, "\n";

	# maybe we received a new CSRF token
	auth_find_csrf_token($res);

	return $c;
}

sub auth_none($)
{
	return undef unless(defined($ua));

	my $url = shift;

	my $req = HTTP::Request->new(POST => $url);
	$res = $ua->request($req);

	# check if e were successful
	print "\tAuth::auth_none: HTTP code: ", $res->code, "\n" if($cnf_dbg);

# 	$cookie_jar->save;
	my $c = $res->header('Set-Cookie');
	return undef if(not defined($c) or length($c) == 0);
# 	print "DEBUG: cookie :", $c, "\n";
	return $c;
}

sub auth_get($;$;$)
{
	return undef unless(defined($ua));

	my $url = shift;
	my $auth_string = shift;
	my $regex = shift;

	my $req = HTTP::Request->new(GET => $url."/?".$auth_string);

	$res = $ua->request($req);

	# check if e were successful
	print "\tAuth::auth_get: HTTP code: ", $res->code, "\n" if($cnf_dbg);

	return undef if($res->code >= 400);
	if(defined($regex) and length($regex))
	{
# 		print "DEBUG: test regex\n";
		return undef if($res->content =~ /$regex/);
	}

	$cookie_jar->save;
	my $c = $res->header('Set-Cookie');
	return undef if(not defined($c) or length($c) == 0);
	return $c;
}

sub auth_cookie($;$;$)
{
	return undef unless(defined($ua));

	my $url = shift;
	my $regex = shift;
	my $cookie = shift;

	return auth_post_with_cookie($url, undef, $regex, $cookie); # XXX hm, or use GET?
}

sub auth_basic($)
{
}

sub auth_digest($)
{
}

sub add_payload($)
{
}

sub deauth_get($)
{
	return undef unless(defined($ua));

	my $url = shift;

	my $req = HTTP::Request->new(GET => $url);
	$res = $ua->request($req);

	# check if e were successful
	print "\tAuth::deauth_get: HTTP code: ", $res->code, "\n" if($cnf_dbg);
	return 0 if($res->code != 200);
	return 0 if($res->code != 302);

# 	return $res->header('Set-Cookie') if(defined($res->header('Set-Cookie')));
	return 1;
}

sub deauth_post($;$)
{
	return undef unless(defined($ua));

	my $uri = URI->new(shift);
	my $regex = shift;

	my $url = sprintf("%s://%s:%i", $uri->scheme, $uri->host, $uri->port, $uri->path);
	my $form = $uri->as_string;
	$form =~ s/$url//i;
	if(defined($csrf_token) and (length($csrf_token)))
	{
		$form = $csrf_token."&".$form;
	}

	my $req = HTTP::Request->new(POST => $url);

	# build header
# 	$req->header('Accept'=>"*/*");
# 	$req->header('Content-length'=>length($form));
# 	$req->content_type("application/x-www-form-urlencoded");
	$req->content($form);

	print "DBG: deauth_post: HTTP request:", Dumper($req) if($cnf_dbg > 1);

	# send request
	$res = $ua->request($req);
	# check if e were successful
	print "\tAuth::deauth_post: HTTP code: ", $res->code, "\n" if($cnf_dbg);

	return undef unless($res->code == 200 or $res->code == 301 or $res->code == 307);
	if(defined($regex) and length($regex))
	{
		return undef unless($res->content =~ /$regex/); # lock for something like "Logout sucessful"
	}

	my $c = $res->header('Set-Cookie');
	return undef if(not defined($c) or length($c) == 0);
	return $c;
}

sub set_cookie($)
{
	return undef unless(defined($ua));
	my ($k, $v) = split /=/; shift;
	$ua->cookie_jar->set_cookie( "1", $k, $v, "/", "", "", "", 0, 0, 0, undef);
	$ua->cookie_jar->save;
}

sub unset_cookie($)
{
	return undef unless(defined($ua));
}

sub enable_cookie()
{
	$cnf_cookie_enable = 1;
	# load backup jar
}

sub disable_cookie()
{
	$cnf_cookie_enable = 0;
	# save to backup jar and clear current jar
}

my @cookie_fields = qw(Comment CommentURL Discard Domain Expires Max-Age Path Port Secure Version);
sub split_cookie($) # XXX this one doesnt really work
{
	my @f = ();
	foreach (split(/ /, shift))
	{
		chomp;
		next unless /.*=.*/;
		next if /Path=/i;
		next if /Expires=/i;
		$_ =~ s/;$//;
		push @f, $_;
	}
	return @f;
}

sub split_cookie2($)
{
	my $cstr = shift;
	my @c = ();
	foreach (split(/,/, $cstr))
	{
		chomp;
		$_ =~ s/^\s+//;
		push @c, $_;
	}
	return @c;
}

sub extract_cookie($;@)
{
	my $cn = shift;
	my @c = shift;
	foreach (@c)
	{
		return $_ if /$cn/i;
	}
	return undef;
}

# sub split_cookie_attr($)
# {
# 	my $cstr = shift;
# 	my @c = split_cookie($cstr);
# 	# XXX
# 	return @c;
# }

# sufficient if only one cookie is equal
sub compare_cookie_lax($;$)
{
	my $c1 = shift;
	my $c2 = shift;

	my @c1 = split_cookie($c1);
	my @c2 = split_cookie($c2);

	foreach my $tmp1 (@c1)
	{
		foreach my $tmp2 (@c2)
		{
			return 1 if(lc($tmp2) eq $tmp1);
		}
	}
	return 0;
}

# sufficient only if ALL cookies are equal
sub compare_cookie_strict($;$)
{
	my $cook1 = shift;
	my $cook2 = shift;

	my @c1 = split_cookie($cook1);
	my @c2 = split_cookie($cook2);

	# fail if length unequal
	return 0 if($#c2 != $#c1);

	foreach my $tmp1 (@c1)
	{
		my $matched = 0;
		foreach my $tmp2 (@c2)
		{
# 			print "COMPARE: $tmp1 with $tmp2\n";
			$matched = 1 if(lc($tmp2) eq $tmp1);
		}
# 		print "NONE MATCHED\n" unless($matched);
		return 0 unless($matched);
	}
	return 1;
}


1;
