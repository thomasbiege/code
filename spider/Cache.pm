#!/usr/bin/perl
use strict;
use utf8;

package Cache;

use LWP;
use LWP::Simple;
#use LWP::Debug qw(+);
use HTTP::Status;
#use Cwd;
use Data::Dumper;
use File::MimeInfo::Magic;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use URI::Escape;
use POSIX;

our $cache = {};
our $cookie_jar_file = undef;
our $cookie_jar = undef;
our $cnf_dbg = 0;

my $init = 0;
my $cache_dir;
my $cache_dir_abs;

sub init($;$)
{
	my $dir = shift;
	mkdir $dir;

	my $f = shift;
	$cookie_jar_file = $f if(defined($f));
	$cookie_jar = HTTP::Cookies->new(file => $cookie_jar_file, autosave => 1);

	$init = 1;
	$cache_dir = $dir."/";
	$cache_dir_abs = getcwd()."/".$cache_dir;
	return $init;
}

sub deinit($)
{
	return undef unless $init;

# 	write("cache.txt");

	$init = 0;
	return $init;
}

sub get_cachedir()
{
	return undef unless $init;
	return $cache_dir;
}

sub get_cachedirabs()
{
	return undef unless $init;
	return $cache_dir_abs;
}

sub write($)
{
	return undef unless $init;

	my $fn = shift;
	open FD, "> ".$fn || return undef;
	my $i = 0;
	foreach my $key (keys %$cache)
	{
		print FD "$key|$cache->{$key}->{'url'}|$cache->{$key}->{'mime_type'}\n";
		$i++;
	}
	close FD;

	return $i; # records written
}

sub read($)
{
	return undef unless $init;

	# XXX read cache.txt and init $cache href

	my $fn = shift;
}

sub url_of($)
{
	return undef unless $init;
	my $fn = shift;
# 	print "cache: url_of($fn)\n";
	return $cache->{$fn}->{'url'};
}

sub size_of($)
{
	return undef unless $init;
	my $fn = shift;
# 	my $s = -s $cache_dir_abs.$fn;
# 	printf "DEBUG SIZE: $cache_dir_abs.$fn -> $s\n";
	return (-s $cache_dir_abs.$fn);
}

sub mimetype_of($)
{
	return undef unless $init;
	my $fn = shift;
# 	print "cache: mimetype_of($fn)\n";
	return $cache->{$fn}->{'mime_type'};
}

sub key_of($)
{
	return undef unless $init;
	my $url = shift;
# 	print "cache: key_of($url)\n";
	return md5_hex(uri_escape_utf8($url));
}

sub cache_url($)
{
	return undef unless $init;

	my $url = shift;
	$url =~ s/feed://i;
	my $fn = mirror_content($url);
	my $ct = detect_content($cache_dir.$fn);

	$cache->{$fn}->{'url'} = $url;
	$cache->{$fn}->{'mime_type'} = $ct;
# 	print "cache: cache_url($url): $fn, $ct\n";
	return $fn; # also key for our cache href
}

sub mirror_content($)
{
	return undef unless $init;

	my $url = shift;
	my $fname = key_of($url);
	my $rc = mirror_with_auth($url, $cache_dir.$fname);
	print "cache: mirror_content($url): ERROR = $rc\n" if is_error($rc);
# 	print "cache: mirror_content($url): ", status_message($rc),"\n" unless(not defined($rc) and $rc == RC_OK);
	return $fname;
}

sub mirror_with_auth($;$)
{
	my $uri = URI->new(shift);
	my $cache_fname = shift;

	my $ua = LWP::UserAgent->new;
	$ua->agent("WEBCACHE/0.1");
	$ua->cookie_jar($cookie_jar);

	print "cache: mirror_with_auth($uri, $cache_fname, ", Dumper($cookie_jar), ")\n" if($cnf_dbg);

	return $ua->mirror( $uri, $cache_fname); # XXX no real mirroring :(
}

sub detect_content($)
{
	return undef unless $init;

	my $fname = shift;
	my $cont_type = "unknown";

	my $mime_type = mimetype($fname);
	$cont_type = $mime_type if(defined $mime_type);

	return $cont_type;
}

1;