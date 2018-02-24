#!/usr/bin/perl
# use strict;
# use utf8;

package ParsePage;

use LWP;
use LWP::Simple;
use HTTP::Cookies;
#use LWP::Debug qw(+);
use HTML::LinkExtor;
use URI::Escape;
use URI::URL;
use File::Fetch;
use File::Basename;
use Data::Dumper;
use Image::Magick;
use Archive::Tar;
use POSIX;

my $size_total = 0;
my $urls_total = 0;

our $cookie_jar = undef;
our $cookie_jar_file = "$ENV{'HOME'}/.webauth_cookies.dat";


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


# use Spider;
use Cache;

sub init($)
{
	my $f = shift;
	$cookie_jar_file = $f if(defined($f));
	$cookie_jar = HTTP::Cookies->new(file => $cookie_jar_file, autosave => 1);

	mkdir $_ foreach(("vcs","vcf","docs","pics","feeds", "cache", "audio", "sheets", "video", "javascript"));

	$size_total = 0;

	Cache::init("cache", $cookie_jar_file);
}

sub deinit()
{
# 	my $arg = shift;
	Cache::deinit("");
}

sub parse_url($)
{
	my $url = shift;
	chomp $url;
	my $browser = LWP::UserAgent->new();
	my $webdoc = $browser->request(HTTP::Request->new(GET => $url));
	return unless($webdoc->is_success);
	return unless($webdoc->content_type eq 'text/html');
	my $base = $webdoc->base;

	print "ParsePage: web-page: '$url'\n";

	open FD_FUZZ,   ">> fuzz.txt";
	open FD_SCHEME, ">> scheme.txt";
	foreach(HTML::LinkExtor->new->parse($webdoc->content)->eof->links)
	{
		my($tag, %links) = @$_;
		#next unless($tag eq "a");
		my $link;
		foreach $link (values %links)
		{
			#print "\t$tag -> $link\n";
			my $str_link = url($link, $base)->abs->as_string;
			chomp($str_link);
			my $where = undef;

			next if($str_link =~ /.*\/$/); # index links, just to speed things up and still allow external links
			next if(just_an_index($str_link, $url)); # ignore fragments for the same page

			my $f = Cache::cache_url($str_link);
			my $s = Cache::size_of($f);
			my $t = Cache::mimetype_of($f);
# 			print "\tCached URL ", $str_link, " with $t at ", Cache::get_cachedir(), "/", Cache::key_of($str_link), "\n";

			$s = 0 unless(defined $s);
			$size_total += $s;
			$t = "unknown" unless(defined $t);

# 			print "\tfound: '$str_link' ($f [$s bytes] -> $t)\n" unless($t =~ /text\/html/i);

			if(suitable_for_fuzzing($str_link))
			{
				print FD_FUZZ "$str_link\n";
			}
			if(interesting_scheme($str_link, ("http", "https")))
			{
				print FD_SCHEME "$str_link\n";
			}


			fetch_content($str_link, $f, $t);
			$urls_total++;
		}
	}
	close FD_FUZZ;
	close FD_SCHEME;

# 	return $size_total;
}

sub bytes_downloaded()
{
	return $size_total;
}

sub urls_processed()
{
	return $urls_total;
}

sub resize_all_images()
{
	image_resize($_, 150) foreach(@pics_fn_all);

	@pics_fn_all = ();
	$pics_idx = 0;
}

sub unify_emails()
{
	system "cat email.txt | sort -u > email_unique.txt" if -f "email.txt"; # XXX dirty hack
}

sub unify_fuzz()
{
	system "cat fuzz.txt | sort -u > fuzz_unique.txt" if -f "fuzz.txt"; # XXX dirty hack
}

sub just_an_index($;$)
{
	my $baseurl = shift;
	my $url = shift;

	$baseurl = uri_escape_utf8($baseurl);
	$url     = uri_escape_utf8($url);

	if($url =~ /(.*)\:\:\/(.*)#(.*)/)
	{
		my $path_query = $2;
		if($baseurl =~ /(.*)\:\:\/(.*)/)
		{
			return 1 if(URI::eq( $path_query, $2));
		}
	}
	else
	{
		return 0
	}
}

sub suitable_for_fuzzing($)
{
	my $url = shift;
	my $uri = URI->new($url);

	return 1 if(defined $uri->query());
	return 0;
}

sub interesting_scheme($;@)
{
	my $url = shift;
	my @scheme_not_interesting = @_;
	my $uri = URI->new($url);
	my $scheme = $uri->scheme();

	foreach my $s (@scheme_not_interesting)
	{
		return 0 if($s =~ /^$scheme/i);
	}
	return 1;
}

our @vcard_fn_all;
our $vcard_idx = 0;
our @doc_fn_all;
our $doc_idx = 0;
our @cal_fn_all;
our $cal_idx = 0;
our @xls_fn_all;
our $xls_idx = 0;
our @vid_fn_all;
our $vid_idx = 0;
our @aud_fn_all;
our $aud_idx = 0;
our @pic_fn_all;
our $pic_idx = 0;
our @rss_fn_all;
our $rss_idx = 0;
our @js_fn_all;
our $js_idx = 0;

sub fetch_content($;$;$)
{
	my $url = shift;
	my $f = shift;
	my $t = shift;

	my $uri = URI->new($url);

	my $fn = undef;
	my $cn = undef;

	my $uri_file = basename($uri->path);
	my $uri_contenttype = undef;

	# calendar
	if($uri_file =~ /(.*\.ics)/i || $uri_file =~ /(.*\.vcs)/i)
	{
		$fn = "vcs/".$1;
		$cal_fn_all[$cal_idx] = $fn;
		$cal_idx++;
		$cn = "calendar";
	}
	elsif($uri_file =~ /(.*\.pdf)/i || $t =~ /application\/pdf/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".pdf" unless(defined $fn);
		$fn = "docs/".$fn;

		$doc_fn_all[$doc_idx] = $fn;
		$doc_idx++;
		$cn = "PDF";
	}
	elsif($uri_file =~ /(.*\.doc)/i || $t =~ /application\/msword/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".doc" unless(defined $fn);
		$fn = "docs/".$fn;

		$doc_fn_all[$doc_idx] = $fn;
		$doc_idx++;
		$cn = "MSWord";
	}
	elsif($uri_file =~ /(.*\.txt)/i || $t =~ /text\/ascii/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".txt" unless(defined $fn);
		$fn = "docs/".$fn;

		$doc_fn_all[$doc_idx] = $fn;
		$doc_idx++;
		$cn = "TXT";
	}
	elsif($uri_file =~ /(.*\.xls*)/i || $t =~ /application\/vnd\.ms\-excel/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".xls" unless(defined $fn);
		$fn = "sheets/".$fn;

		$doc_fn_all[$doc_idx] = $fn;
		$doc_idx++;
		$cn = "MSExcel";
	}
	elsif($uri_file =~ /(.*\.jp.*g)/i || $t =~ /image\/jpeg/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".jpg" unless(defined $fn);
		$fn = "pics/".$fn;

		$pic_fn_all[$pic_idx] = $fn;
		$pic_idx++;
		$cn = "JPEG";
	}
	elsif($uri_file =~ /(.*\.png)/i || $t =~ /image\/.*/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".png" unless(defined $fn);
		$fn = "pics/".$fn;

		$pic_fn_all[$pic_idx] = $fn;
		$pic_idx++;
		$cn = "PNG";
	}
	elsif($uri_file =~ /(.*\.mp3)/i || $t =~ /audio\/mpeg/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".mp3" unless(defined $fn);
		$fn = "audio/".$fn;

		$aud_fn_all[$aud_idx] = $fn;
		$aud_idx++;
		$cn = "MP3";
	}
	elsif($uri_file =~ /(.*\.mp4)/i || $t =~ /video\/mp4/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".mp4" unless(defined $fn);
		$fn = "video/".$fn;

		$vid_fn_all[$vid_idx] = $fn;
		$vid_idx++;
		$cn = "MP4";
	}
	elsif($t =~ /application\/rss\+xml/i)
	{
		$fn = $f.".xml";
		$fn = "feeds/".$fn;

		$rss_fn_all[$rss_idx] = $fn;
		$rss_idx++;
		$cn = "RSS feed";
	}
	elsif($t =~ /application\/atom\+xml/i)
	{
		$fn = $f.".xml";
		$fn = "feeds/".$fn;

		$rss_fn_all[$rss_idx] = $fn;
		$rss_idx++;
		$cn = "Atom feed";
	}
	elsif($url =~ /.*\?vcard=(\d+).*/ || $uri_file =~ /(.*\.vcf)/i || $t =~ /text\/directory/i)
	{
		my $vcard_id = $1;

		unless(defined $vcard_id)
		{
			$vcard_id = "rnd".int(rand(65536));
		}
		elsif($1 =~ /.*\.vcf/i)
		{
			$fn = "vcf/".$1;
		}
		else
		{
			$fn = "vcf/vcard_".$vcard_id.".vcf";
		}

		$vcard_fn_all[$vcard_idx] = $fn;
		$vcard_idx++;
		$cn = "vcard";
	}
	elsif($uri_file =~ /(.*\.js)/i)
	{
		$fn = $1 if(defined $1);
		$fn = $f.".js" unless(defined $fn);
		$fn = "javascript/".$fn;

		$js_fn_all[$js_idx] = $fn;
		$js_idx++;
		$cn = "JavaScript";
	}
	else
	{
		return undef;
	}

	# we just link to the cached file
	my $c = Cache::get_cachedir();
	$c = "cache" unless(defined $c);
	$c = "../".$c;
	symlink($c."/".$f, $fn);
	print "\t\tsaved $cn to $fn\n";

	return $fn;
}

sub extract_url($)
{
	my $str = shift;

	my $url = undef;

	# 1. href=
	$url = $1 if($str =~ /href\s*=\s*([\w\d\-\._\/\/\:\?&=#]+)/i);
	chomp $url if defined $url;

	return $url;
}

sub extract_email($)
{
	my $str = shift;

	my $email = undef;

	# 1. mailto:
#	$email = $1 if($str =~ /mailto:(.*)/i);

	# 2. regex
# 	unless defined $email
# 	{
 		$email = $1 if($str =~ /([\w\d_\-%]+\@[\w\d_\-\.]+\.[\w]+)/);
# 	}

	# cleanup
	chomp $email if defined $email;

	return $email;
}


sub get_email_addr_from_page($)
{
	my $url = shift;

	my $ua = LWP::UserAgent->new();
	my $webdoc = $ua->request(HTTP::Request->new(GET => $url));
	return undef unless($webdoc->is_success);
	return undef unless($webdoc->content_type eq "text/html");
	my $base = $webdoc->base;

	# extract email addresses
	my @email_all;
	my $i = 0;
# 	foreach(HTML::LinkExtor->new->parse($webdoc->content)->eof->links)
# 	{
# 		my($tag, %links) = @$_;
#
# 		next unless($tag eq "a");
# 		my $link;
# 		foreach $link (values %links)
# 		{
# 			my $str_link = url($link, $base)->abs->as_string;
# 			my $email = extract_email($str_link);
# 			next unless defined $email;
# 			$email_all[$i] = $email;
# 			$i++;
# 		}
# 	}
	unless(mirror($url, "page.html") == RC_NOT_MODIFIED) # XXX use Cache.pm
	{
		open FD, "< page.html";
		while(<FD>)
		{
			my $email = extract_email($_);
			next unless defined $email;
			$email_all[$i] = $email;
			$i++;
		}
		close FD;
	}
	#print "emails: ", Dumper(@email_all);
	return @email_all;
}

sub get_image_and_resize_from_page($)
{
	my $url = shift;
	my @fn_all;
	my $ua = LWP::UserAgent->new();
	my $webdoc = $ua->request(HTTP::Request->new(GET => $url));
	return undef unless($webdoc->is_success);
	return undef unless($webdoc->content_type eq "text/html");
	my $base = $webdoc->base;

	# extract and resize images
	my $i = 0;
	foreach(HTML::LinkExtor->new->parse($webdoc->content)->eof->links)
	{
		my($tag, %links) = @$_;

		next unless($tag eq "img");
		my $link;
		foreach $link (values %links)
		{
			my $str_link = url($link, $base)->abs->as_string;
			my $img_url = undef;
			$img_url = $1 if($str_link =~ /(.*\.jp*g)/i);
			next unless defined $img_url;

			$fn_all[$i] = get_image_and_resize_from_url($img_url);
			$i++;
		}
	}
	return @fn_all;
}

sub get_image_and_resize_from_url($)
{
	my $img_url = shift;
	my $fn = "unknown";
	my $img_fname = undef;

	# fetch image
	#system "curl -O -- $img_url 2>&1 >/dev/null";
	my $ff = File::Fetch->new(uri => $img_url);
	my $where = $ff->fetch() or next;

	# but only jpegs
	$img_fname = $1 if($img_url =~ /.*\/(.*\.jp*g)/i);
	return undef unless defined $img_fname;

	return image_resize($img_fname, 150);
}

sub image_resize($;$)
{
	my $fn = shift;
	my $new_size = shift;
	my $fn_new = "resized_".$fn;

	# resize image
	my $p = new Image::Magick;
	$p->Read($fn);
	my ($p_w, $p_h) = $p->Get('width', 'height');
	my $p_w_new = $new_size;

	my $p_reduce_perc = floor(100/$p_w * ($p_w - $p_w_new));

	my $p_h_new = floor( $p_h - ($p_h * $p_reduce_perc/100));

	if($p_w < $p_w_new)
	{
		#print "\tdo not need to resize ($p_w) image $img_fname\n";
		symlink($fn, $fn_new);
	}
	else
	{
		#print "\tresize image $img_fname ($p_w x $p_h) to width ${p_w_new}px and height ${p_h_new}px ($p_reduce_perc%)\n";
		$p->Resize(width=>${p_w_new}, height=>${p_h_new});
		$p->Write($fn_new);
	}

	return $fn_new;
}

sub parse_vcard($)
{
	my $fname = shift;
	my %vh = ();

	$vh{'name'}	= undef;
	$vh{'fullname'}	= undef;
	$vh{'telwork'}	= undef;
	$vh{'telhome'}	= undef;
	$vh{'email'}	= undef;
	$vh{'photo'}	= undef;
	$vh{'addrhome'}	= undef;

	open FD, "< ".$fname;
	while(<FD>)
	{
		$vh{'name'}	= $1			if(/N\:([\w\d\.\-_ ]+)/);
		$vh{'fullname'}	= $1			if(/FN\:([\w\d\.\-_ ]+)/);
		$vh{'telwork'}	= $1			if(/TEL\;WORK\;VOICE\:([\d\-_ \/]+)/);
		$vh{'telhome'}	= $1			if(/TEL\;HOME\;VOICE\:([\d\-_ \/]+)/);
		$vh{'email'}	= $1			if(/EMAIL\;INTERNET\:([\w\d\.\-_ @]+)/);
		$vh{'photo'}	= $1			if(/PHOTO\:([\w\d\.:\/\-_\?&=]+)/);
		$vh{'addrhome'}	= $1.", ".$3." ".$2	if(/ADR\;TYPE=dom,home,postal,parcel\:\;\;(.*)\;(.*)\;\;(\d+)/);
	}
	close FD;

	chomp($vh{'name'})	if(defined $vh{'name'});
	chomp($vh{'fullname'})	if(defined $vh{'fullname'});
	chomp($vh{'telwork'})	if(defined $vh{'telwork'});
	chomp($vh{'telhome'})	if(defined $vh{'telhome'});
	chomp($vh{'email'})	if(defined $vh{'email'});
	chomp($vh{'photo'})	if(defined $vh{'photo'});
	chomp($vh{'addrhome'})	if(defined $vh{'addrhome'});

	# fix photo links for special pages
	$vh{'photo'} =~ s/user_pagesP/user_pages\/P/;

	# fetch and resize photo to make freemind faster
	$vh{'photo'} = get_image_and_resize_from_url($vh{'photo'});

	return %vh;
}

sub make_vcard($;$)
{
	my $fname = shift;
	my $vh_href = shift;
	my %vh = ();

	$vh{'name'}	= "unknown";
	$vh{'fullname'}	= "unknown";
	$vh{'telwork'}	= "unknown";
	$vh{'telhome'}	= "unknown";
	$vh{'email'}	= "unknown";
	$vh{'photo'}	= "unknown";
	$vh{'addrhome'}	= "unknown";

	$vh{'name'}	= $vh_href->{'name'}    if(defined $vh_href->{'name'});
	$vh{'fullname'}	= $vh_href->{'fullname'}if(defined $vh_href->{'fullname'});
	$vh{'telwork'}	= $vh_href->{'telwork'} if(defined $vh_href->{'telwork'});
	$vh{'telhome'}	= $vh_href->{'telhome'} if(defined $vh_href->{'telhome'});
	$vh{'email'}	= $vh_href->{'email'}   if(defined $vh_href->{'email'});
	$vh{'photo'}	= $vh_href->{'photo'}   if(defined $vh_href->{'photo'});
	if(defined $vh_href->{'addrhome'})
	{
		if($vh_href->{'addrhome'} =~ /([\w\s\-]+\s+[\d\w]+)\s*(\d+)\s*([\w\s\-]+)/i)
		{
			$vh{'addrhome'} = sprintf(";;%s;%s;;%s", $1, $3, $2);
		}
	}

	open  FD, "> ".$fname;
	print FD "BEGIN:VCARD\n";
	print FD "N:",                               $vh{'name'}, "\n";
	print FD "FN:",                              $vh{'fullname'}, "\n";
	print FD "TEL;WORK;VOICE:",                  $vh{'telwork'}, "\n";
	print FD "TEL;HOME;VOICE:",                  $vh{'telhome'}, "\n";
	print FD "EMAIL;INTERNET:",                  $vh{'email'}, "\n";
	print FD "PHOTO:",                           $vh{'photo'}, "\n";
	print FD "ADR;TYPE=dom,home,postal,parcel:", $vh{'addrhome'}, "\n";
	print FD "END:VCARD\n";
	close FD;

	return %vh;
}

sub cleanup()
{
# 	print "cleanup\n";

# 	print "\tunify emails\n";
	unify_emails();

# 	print "\tunify fuzz URLs\n";
	unify_fuzz();

# 	print "\tresize all images\n";
	resize_all_images();
}

1;

