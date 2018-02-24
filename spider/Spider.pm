#!/usr/bin/perl
# use strict;
# use utf8;

package Spider;

use LWP;
use LWP::Simple;
#use LWP::Debug qw(+);
use Data::Dumper;
use Time::Local;
use HTML::LinkExtor;
use HTTP::Cookies;
use URI::URL;
use POSIX;

use Cache;
use Auth;

our $cnf_dbg = 0;

our $cookie_jar = undef;
our $cookie_jar_file = "$ENV{'HOME'}/.webauth_cookies.dat";
our $ua = undef;
our $cnf_cookie_enable = 1;

our $cnf_login_url = undef;
our $cnf_login_method = undef;
our $cnf_login_cred = undef;
our $cnf_login_regex = undef;
our $cnf_cookie_name = undef;
our $cnf_csrf_token_name = undef;
our $cnf_csrf_token_regex = undef;
our $cnf_csrf_uri = undef;
our @cnf_ignore_url = ();


sub init()
{
	
	$cookie_jar = HTTP::Cookies->new(file => $cookie_jar_file, autosave => 1);
	$ua = LWP::UserAgent->new;
	$ua->agent("SPIDER/0.1");
	$ua->cookie_jar($cookie_jar);

	Auth::init($cookie_jar_file);
}

sub deinit()
{
	$cnf_auth_regex = undef;
	Auth::deinit();

}

sub auth()
{
	return undef unless(defined($ua));

	$Auth::cookie_jar->clear;
	$Auth::cookie_jar->clear_temporary_cookies;
	$Auth::csrf_token = undef; # Auth will do it autom. then
	$Auth::csrf_token_name = $cnf_csrf_token_name;
	$Auth::csrf_token_regex = $cnf_csrf_token_regex;
	$Auth::csrf_uri = $cnf_csrf_uri;

	# 1. try login page to get a cookie as attacker
	$cookie = Auth::auth_post($cnf_login_url, $cnf_login_cred, $cnf_login_regex);
	unless(defined($cookie))
	{
		return undef;
	}

	$ua->cookie_jar($Auth::cookie_jar);

	return $cookie;
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

sub spider_deep($;$;$);
sub spider_deep($;$;$)
{
	my $url = URI->new(shift);
	my $depth = shift;
	my $url_href = shift;

	my @url_all;
	my @url_skipped;
	my $i = 0;
	my $j = 0;
	my $db = {};

	return (undef, undef) unless($url->canonical =~ /^(https|http|ftp).*/i);

	return (undef, undef) unless(defined($ua));

# 	$url->canonical();

	my $url_str = url($url)->abs->as_string;
	foreach my $ignurl (@cnf_ignore_url)
	{
		if(index($url_str, $ignurl) >= 0) # url should be ignored
		{
			return (undef, undef) 
		}
	}

	if(defined $url_href->{$url_str}) # url already known?
	{
# 		print "XXX ALREADY KNOWN: ", $url_str, "\n";
		return (undef, undef) 
	}

	$url_all[$i] = $url_str;
	$i++;

	# extract domain
	my $domain = $url->host;
	unless($domain =~ /^[\d\.]+$/)
	{
		$domain = $1 if($domain =~ /[\w\d\-_]+\.(.*)/i);
	}
#$domain = $1 if($domain =~ /http[s]:\/\/[\w\d\-_]+\.([\w\d\-]+\.[\w]+)\/.*/i);

	print "spider $depth: for domain $domain and url $url with depth $depth\n";
	#print ".";

	# no more recursions
	return @url_all if($depth <= 0);


	# go!
	my $req = HTTP::Request->new(GET => $url);
# 	$cookie_jar->add_cookie_header($req); # if($cnf_cookie_enable);
	my $webdoc = $ua->request($req);
# 	print "COOKIE REQUEST:", Dumper($req->header('Cookie')), "\n";
# 	print $webdoc->as_string;
# 	print "XXX RET CODE: ",  status_message($webdoc->code), "\n";
	return (undef,undef) unless($webdoc->is_success);
	return (undef,undef) unless($webdoc->content_type =~ /text\/html/i);
	my $base = $webdoc->base;

	# build up spidb
	$db->{'date'}		= localtime();
	$db->{'fuzzable'}	= ParsePage::suitable_for_fuzzing($url);
	$db->{'forced_browsing'}= -1;
	$db->{'head_bypass'}	= -1;
	$db->{'csrf_protected'}	= -1; # XXX Utils::csrf_protected($url, "test=bla", $cnf_login_regex);

	unless($url_str =~ /$cnf_login_url\?*.*/) # ignore login page even with different params
	{
# 		print "XXX: $url_str vs. $cnf_login_url\n";

		if(Utils::is_auth_needed($url, $cnf_login_regex))
		{
			$db->{'forced_browsing'}= Utils::forced_browsing($url, $cnf_login_regex);
			$db->{'head_bypass'}	= Utils::head_bypass($url, $cnf_login_regex);
	# 		$db->{'csrf_protected'}	= Utils::csrf_protected($url, "test=bla", $cnf_login_regex);
		}
	}

	$url_href->{$url_str} = $db;

# 	print "DBEUG: ", Dumper($url_href) , "\n";

	foreach(HTML::LinkExtor->new->parse($webdoc->content)->eof->links)
	{
		my($tag, %links) = @$_;

		next unless($tag eq 'a');
		my $link;
		foreach $link (values %links)
		{
			my $str_link = url($link, $base)->abs->as_string;
			my $nxt_url = URI->new($str_link);
			next unless(defined $nxt_url);

			$nxt_url->canonical();

# 			print "\tXXX NXT URL: ", $nxt_url, "\n";

			# detect loops
			if($nxt_url == $url) # == more efficient
			{
# 				print "\tloop skipped...\n";
				next;
			}

# 			print "DEBUG: $nxt_url\n";

			# verify this url does not point outside the original domain
			unless($nxt_url =~ /$domain/i)
			{
# 				print "\tXXX SKIPPED URL: ", $nxt_url, "\n";
# 				print "\tskipped ($nxt_url->host vs. $domain)...\n";
				$url_skipped[$j] = url($nxt_url)->abs->as_string;
				$j++;
				next;
			}

			#next if($nxt_url->as_string =~ /.*#[\w\d\s%]$/i); # fragments will be ignored
			next if($nxt_url->fragment);


			# recursivly call spider_deep() to search deep
			my (@url_new, @url_void) = spider_deep($nxt_url, $depth-1, $url_href);

			foreach(@url_new)
			{
				$url_all[$i] = $_;
				$i++;
			}
			foreach(@url_void)
			{
				$url_skipped[$i] = $_;
				$j++;
			}
		}
	}

	# sort and unify
# 	print "\n";
	return (@url_all, @url_skipped);
}

1;
