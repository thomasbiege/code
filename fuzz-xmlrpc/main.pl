#!/usr/bin/perl

use strict;
use utf8;
use Data::Dumper;
use LWP::UserAgent;
use HTTP::Request::Common;
use MIME::Base64;
use File::MimeInfo::Magic;
use File::Basename;
use FileHandle;
use URI::Escape;
use XML::Simple;

use Cwd qw(realpath);
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
    push @INC, realpath(sprintf("%s/%s/%s", $ENV{PWD}, dirname($f), "./fuzz_pm/"));
}

use Fuzz;

#
# MAIN
#
our %interesting_rc	= (
			500 => "500",
			404 => "404",
			200 => "200"
			);

our $fn_targets		= "target-list.txt";
our $auth_user		= "studio";
our $auth_pass		= "isfsfsfs";
our $cnf_scheme		= "http://";
our $cnf_host		= "mayo.example.de";
our $cnf_baseurl	= "";
our $cnf_proxy		= "";
our $cnf_test		= 0;
our $cnf_simulate	= 0;
our $cnf_interactive	= 0;
our $cnf_interesting	= 0;
our $cnf_noget		= 0;
our $cnf_delete		= 0;
our $cnf_debug		= 0;
our $cnf_log_http	= 0;
our $cnf_log_fuzz	= 0;
our $cnf_fuzz_dontesc	= 0;
our $cnf_file_pat	= "";
our $cnf_cnt_type	= "text/xml";
our $perf_cnt_url_total	= 0;
our $perf_cnt_url_succ	= 0;
our $ua;


my $fuzz_none = 1;

# parse arg: auth=user:pass file.txt http[s]://baseurl proxy=uri
foreach(@ARGV)
{
	# proxy, debug flag, test mode, simulate mode
	$cnf_proxy		= $1	if(/proxy=(.*)/i);	# HTTP proxy
	$cnf_debug		= 1	if(/log=debug/i);	# just more info
	$cnf_log_http		= 1	if(/log=http/i);	# just more info
	$cnf_log_fuzz		= 1	if(/log=fuzz/i);	# just more info
	$cnf_test		= 1	if(/mode=test/i);	# just use GET
	$cnf_simulate		= 1	if(/mode=simulate/i);	# don't send traffic
	$cnf_delete		= 1	if(/mode=delete/i);	# DELETE created entries
	$cnf_interactive	= 1	if(/mode=interactive/i);# wait after each fuzzed request
	$cnf_interesting	= 1	if(/mode=interesting/i);# wait after each fuzzed request only if return value from server is interesting
	$cnf_noget		= 1	if(/mode=noget/i);	# do not trigger a HTTP GET and do not analyze result from server

	# fuzz modes
	if(/fuzz=help/i)
	{
		print "fuzz modes available:";
		print " '$_'" foreach (keys %Fuzz::h_fuzzconf);
		print "\n\tor just 'all' (w/o integer overflow fuzzing)";
		print "\n\twhen you use 'file' do not forget to add '=pattern' like 'fuzz=file=fuzzdb/dir/*.txt\n";
		exit 0;
	}
	if(/fuzz=(.*)/i)
	{
		my $fm = $1;
		die ("fuzz mode 'file' needs a pattern argument\n") if($fm =~ /^file[=]*$/i);
		if($fm =~ /^file=(.*)$/i)
		{
			$fm = "file";
			$cnf_file_pat = $1;
			$Fuzz::file_pat = $cnf_file_pat;
		}
		
		unless(defined($Fuzz::h_fuzzconf{$fm}) or $fm =~ /all/i)
		{
			print "unknown fuzz mode: $fm\n";
			exit 0;
		}
		if($fm =~ /all/i)
		{
			foreach(keys %Fuzz::h_fuzzconf)
			{
				next if /(int32|int64|file)/;
				$Fuzz::h_fuzzconf{$_} = 1;
			}
		}
		else
		{
			$Fuzz::h_fuzzconf{$fm} = 1;
		}
		$fuzz_none = 0;
	}

	# data related options
	if(/data=(.*)/i)
	{
		my $opt = $1;
		if($opt =~ /dontescape/i) # do not escape fuzz string
		{
			$cnf_fuzz_dontesc = 1;
		}
		else
		{
			$cnf_cnt_type = $opt; # http content type
		}
	}

	# basic auth credentials
	if(/auth=(.*):(.*)/)
	{
		$auth_user = $1;
		$auth_pass = $2;
	}

	# target list file
	$fn_targets = $1 if(/(target.*\.txt)/i);

	# target host to test
	if(/(http[s]*:\/\/)(.*)/i)
	{
		$cnf_scheme = $1;
		$cnf_host = $2;
	}

	if(/help/i)
	{
		print("usage:\tfuzz=help [help]\n\t[log=[debug|http|fuzz]]\n\t[mode=[test|simulate|delete|interactive|interesting|noget]]\n\t[data=[dontescape|http content-type]]\n\t[proxy=host:port] [auth=user:pass]\n\t[targetlist.txt] [http[s]]://target.com\n");
		exit 0;
	}
}
die ("Error: file $fn_targets does not exist.") unless -e $fn_targets;
$cnf_baseurl = $cnf_scheme.$cnf_host;


die("Use fuzz=<mode> or fuzz=all") if $fuzz_none;

# target list parsing
my %h_targets = parse_targetlist($fn_targets);
die("error while parsing target file") if(keys(%h_targets) == 0);
print Dumper(%h_targets) if($cnf_debug);


# print config
$ENV{'PERL_LWP_SSL_VERIFY_HOSTNAME'} = 0;
print
"Config:\n\tuser: $auth_user
\tpassword: $auth_pass
\ttarget list: $fn_targets
\tbase url: $cnf_baseurl
\tproxy: $cnf_proxy
\tcontent-type: $cnf_cnt_type
\tfuzz mode:";
foreach (keys %Fuzz::h_fuzzconf)
{
	if($Fuzz::h_fuzzconf{$_})
	{
		unless ($_ =~ /^file$/)
		{
			print " ", $_ 
		}
		else
		{
			print " $_ ($cnf_file_pat)"; 
		}
	}
}
print "\n\n";


# User Agent
$ua = LWP::UserAgent->new();
$ua->proxy(['http'], $cnf_proxy);
$ua->agent("XMLRPC-FUZZER/0.2 ");


# go!
unless($cnf_test)
{
	print "Start Fuzzing:\n";
	fuzz(\%h_targets);
}
else
{
	print "Start Testing:\n";
	test(\%h_targets);
}

print "\nEntries fuzzed    : $perf_cnt_url_total\n";
print "Entries suspicious: $perf_cnt_url_succ\n";

print "\ndone\n";

0;

#
# SUBS
#
sub fuzz($)
{
	my $t = shift;
	my %ht = %$t;

	# 0 means an error occured that do not
	#         need further processing
	# 1 means the request was somehow successful
	#         and should be further analyzed
	my %fuzz_success =
	(
		500 => 1,	# parsing error leads to internal error
		201 => 1,	# PUT
		200 => 1,	# POST
	);

	# uh, brain dead
	my $fn = $cnf_host;
	$fn =~ s/\./_/g;
	$fn = "outcome-".$fn.".txt";
	print "\toutcome file: $fn\n";
	foreach my $path (keys %ht)
	{
		foreach my $hm ($ht{$path})
		{
			foreach my $method (keys %$hm)
			{
				print "\ttarget: $method $cnf_baseurl$path";

				next unless($method =~ /POST/i or $method =~ /PUT/i); # XXX also allow GET urlfuzz

				my $tmpl = $hm->{$method}->{"tmpl"};
				my $new = $hm->{$method}->{"new"};

				if($tmpl =~ /.*\.xml$/i)
				{
					fuzz_xml($fn, $method, $path, $tmpl, $new);
				}
				elsif($tmpl =~ /^urlfuzz$/i)
				{
					fuzz_url($fn, $method, $path, $new);
				}
				else
				{
					fuzz_file($fn, $method, $path, $tmpl, $new);
				}
			}
		}

	}
}

sub fuzz_xml($;$;$;$;$)
{
	my $fn     = shift;
	my $method = shift;
	my $path   = shift;
	my $tmpl   = shift;
	my $new    = shift;

	# 0 means an error occured that do not
	#         need further processing
	# 1 means the request was somehow successful
	#         and should be further analyzed
	my %fuzz_success =
	(
		500 => 0,	# parsing error leads to internal error
		201 => 1,	# PUT
		200 => 1,	# POST
	);

	print " (xml fuzz)\n";
	open my $FD, ">> $fn" or return 1;
	$FD->autoflush(1);
	printf $FD "\n\nTimestamp: %s\n------------------------------\n\n", timestamp();

	# go!
	$Fuzz::log_fuzz = $cnf_log_fuzz;
	Fuzz::reset_all();

	my $iter = 0;
	while(1)
	{
		my $p = $path;
		$iter++;
		my $r = int(rand(1000000));
		$p =~ s/RND/$r/g;
		$p =~ s/INC/$iter/g;

		my ($type, $cnt) = gen_fuzz_xml($tmpl, \%Fuzz::h_fuzzconf);
		last unless(defined($type) and defined($cnt)); # no more fuzz strings/files available

		# 1. HTTP request
		my @rc = http_request_xmlrpc($method, $p, $cnt);

		$perf_cnt_url_total++;


		# 2. HTTP response code handling
		my $skip_rest = 0;
		unless(defined($fuzz_success{$rc[0]}))
		{
			print "\t\tOutcome: '$rc[1]' -> unknown [$type]\n" unless($cnf_simulate);
			$skip_rest = 1;
		}
		if($fuzz_success{$rc[0]} == 0 and not $skip_rest)
		{
			my $errdesc = "";
			# some services, like WebYaST, return an error description XXX config?
			$errdesc = ": $1" if($rc[3] =~ /<description>(.*)<\/description>/);
			print "\t\tOutcome: '$rc[1]' -> unhandled, see log files [$type]$errdesc\n" unless($cnf_simulate);
			printf $FD "%s", log_str($rc[0], $method, $p, $cnt, $type, $rc[4], 0, ("empty"));
			$skip_rest = 1;
		}

		if($cnf_interactive)
                {
                        print "\t\tpress RETURN to continue...";
                        read STDIN, my $tmp, 1;
                }
		if($cnf_interesting and defined($interesting_rc{$rc[0]}))
                {
                        print "\t\t$rc[1]: press RETURN to continue...";
                        read STDIN, my $tmp, 1;
                }
		next if $skip_rest;


		# 3. Content-Type checking
		unless($rc[2] =~ /application\/xml/)
		{
			print "\t\tOutcome: '$rc[1]' -> unknown content-type '$rc[2]' [$type]\n" unless($cnf_simulate);
			next;
		}
		print "\t\tOutcome: '$rc[1]' -> $rc[2] [$type]\n" unless($cnf_simulate);


		# 4. HTTP GET request to get a compareable result
		unless($cnf_noget)
		{
			my @res_get;
			my $path_get = $p;
			if($method eq "POST" and $new) # PUT and some POSTs does not need extra handling
			{
				# this is more tricky because a new entry was created and we
				# do not know the ID directly and the xml tag depends on the
				# implementation :( XXX
				# we can automatically detect it by looking for incrementing
				# integers ot maybe random integers? *phew*
				unless($rc[3] =~ /<id type="integer">(\d+)<\/id>/)
				{
					print "\t\tOutcome: '$rc[1]' -> unable to find ID [$type]\n" unless($cnf_simulate);
					next;
				}
				my $id = $1;
				$path_get =~ s/\.xml$/\/$id\.xml/;
			}
			@res_get = http_request_get($path_get);

			unless($res_get[0] == 200)
			{
				my $errdesc = "";
				# some services, like WebYaST, return an error description XXX config?
				$errdesc = ": $1" if($res_get[3] =~ /<description>(.*)<\/description>/);
				print "\t\tGET Outcome: '$res_get[1]' -> ERROR for GET $path_get [$type]$errdesc\n";
				next;
			}

			# delete entry if requested
			if($cnf_delete and $new)
			{
				http_request_delete($path_get);
				print "\t\tdeleted created entry\n" if($cnf_debug);
			}


			# 5. Fuzz result analysis
			my $href_xml_tmpl = XMLin($tmpl, KeepRoot => 1);
			my $href_xml_fuzz = XMLin($cnt, KeepRoot => 1);
			my $href_fixed = ();
			my $href_xml_res  = XMLin($res_get[3], KeepRoot => 1, NoAttr => 1);

			# fix difference in XML tags from SLMS
			$href_fixed = ();
			foreach my $k1 (keys %$href_xml_res)
			{
				foreach my $k2 (keys %{$href_xml_res->{$k1}})
				{
					my $k_fixed = $k2;
					$k_fixed =~ s/-/_/g;
					$href_fixed->{$k1}->{$k_fixed} = $href_xml_res->{$k1}->{$k2}
				}
			}
			$href_xml_res = $href_fixed;

			#print "\t\tfuzz analysis: \n";
			my @a = Fuzz::analyze(
				$href_xml_tmpl,
				$href_xml_fuzz,
				$href_xml_res,
				$type,
				$rc[0]
			);
# 					print "A: ", Dumper(@a);
			if($a[2] > 0) # we found suspicious entries
			{
				$perf_cnt_url_succ++;
				my @q = @{$a[3]};

				unless($cnf_simulate)
				{
					print "\t\tOutcome: '$rc[1]' -> VERIFY ";
					print "(possible XSS vulnerability)" if($type =~ /html/i);
					print "[$type]\n";
					print "\t\t\t$_\n" foreach(@q);
				}
				printf $FD "log: %s", log_str($rc[0], $method, $p, $cnt, $type, $res_get[3], $a[2], @q);
			}
		} # cnf_noget
	}
	close($FD);

	return 0;
}

sub fuzz_file($;$;$;$;$)
{
	my $fn     = shift;
	my $method = shift;
	my $path   = shift;
	my $tmpl   = shift;
	my $new    = shift;

	# 0 means an error occured that do not
	#         need further processing
	# 1 means the request was somehow successful
	#         and should be further analyzed
	my %fuzz_success =
	(
		500 => 1,	# parsing error leads to internal error
		201 => 1,	# PUT
		200 => 1,	# POST
	);

	print " (file fuzz)\n";
	open my $FD, ">> $fn" or return 1;
	$FD->autoflush(1);
	printf $FD "\n\nTimestamp: %s\n------------------------------\n\n", timestamp();

	# fuzz!
	my $iter = 0;
	# i. loop for mangled files
	do
	{
		my ($type, $cnt) = (undef, undef);
		# keywords in the url path?
		my $p = $path;
		$iter++;
		my $r = int(rand(1000000));
		$p =~ s/RND/$r/g;
		$p =~ s/INC/$iter/g;

		# mangled file
		$type = "mangle";
		$cnt = $tmpl;
		$cnt =~ s/INC/$iter/g; # next fuzzed file

		my $tmpfn = $cnt;
		$tmpfn =~ s/(RND|FUZZ)//g; # cleanup filename for testing
		last unless(-f $tmpfn); # file to upload does not exist


		# ii. filename fuzzing too
		Fuzz::reset_all();
		$Fuzz::log_fuzz = $cnf_log_fuzz;
		my $filenamefuzz = 1;
		my ($type_fn, $fuzz_str) = ("","");
FUZZINNER:	while(defined($type_fn) and defined($fuzz_str) and $filenamefuzz)
		{
			($type_fn, $fuzz_str) = gen_fuzz_str(\%Fuzz::h_fuzzconf);

# 			print "XXX type_fn: $type_fn, fuzz_str: $fuzz_str\n";
			last unless(defined($type_fn) and defined($fuzz_str)); # no more fuzz strings available

			$filenamefuzz = 0 unless(basename($cnt) =~ /(RND|FUZZ)/);

			my $filename = basename($cnt);
			$filename =~ s/RND/$r/g;
			$filename =~ s/FUZZ/$fuzz_str/g;

			# remove keywords from path name to file
			my $file_to_upload = $cnt;
			$file_to_upload =~ s/RND//g;
			$file_to_upload =~ s/FUZZ//g;

			# 1. HTTP request
			my @rc = http_request_file($method, $p, $file_to_upload, $filename);

			$perf_cnt_url_total++;

			if($cnf_interactive)
			{
				print "\t\tpress RETURN to continue...";
				read STDIN, my $tmp, 1;
			}

			# 2. HTTP response code handling
			unless(defined($fuzz_success{$rc[0]}))
			{
				print "\t\tOutcome: '$rc[1]' -> unknown [$type:$type_fn]\n" unless($cnf_simulate);
				next FUZZINNER;
			}
			if($fuzz_success{$rc[0]} == 0)
			{
				my $errdesc = "";
				# some services, like WebYaST, return an error description XXX config?
				$errdesc = ": $1" if($rc[3] =~ /<description>(.*)<\/description>/);
				print "\t\tOutcome: '$rc[1]' -> unhandled, see log files [$type:$type_fn]$errdesc\n" unless($cnf_simulate);
				printf $FD log_str($rc[0], $method, $p, $fuzz_str, $type.":".$type_fn, $rc[4], 0, ("empty"));
				next FUZZINNER;
			}

			# 3. Content-Type checking
			unless($rc[2] =~ /application\/xml/)
			{
				print "\t\tOutcome: '$rc[1]' -> unknown content-type '$rc[2]' [$type:$type_fn]\n" unless($cnf_simulate);
				next FUZZINNER;
			}

			# 4. HTTP GET request to get a compareable result
			my @res_get;
			my $path_get = $p;
			if($method eq "POST" and $new) # PUT and some POSTs does not need extra handling
			{
				# this is more tricky because a new entry was created and we
				# do not know the ID directly and the xml tag depends on the
				# implementation :( XXX
				# we can automatically detect it by looking for incrementing
				# integers ot maybe random integers? *phew*
				unless($rc[3] =~ /<id type="integer">(\d+)<\/id>/)
				{
					print "\t\tOutcome: '$rc[1]' -> unable to find ID [$type:$type_fn]\n" unless($cnf_simulate);
					next FUZZINNER;
				}
				my $id = $1;
				$path_get =~ s/\.xml$/\/$id\.xml/;
			}
			@res_get = http_request_get($path_get); # XXX do we always want to call it?

			unless($res_get[0] == 200)
			{
				my $errdesc = "";
				# some services, like WebYaST, return an error description XXX config?
				$errdesc = ": $1" if($res_get[3] =~ /<description>(.*)<\/description>/);
				print "\t\tOutcome: '$res_get[1]' -> ERROR for GET $path_get [$type:$type_fn]$errdesc\n";
				next FUZZINNER;
			}

			# delete entry if requested
			if($cnf_delete and $new)
			{
				http_request_delete($path_get);
				print "\t\tdeleted created entry\n" if($cnf_debug);
			}


			# 5. Fuzz result analysis XXX
			# GET and compare filename?
		}
FILEMANGLE: } while($tmpl =~ /INC/); # only continue if there are multiple files
	close($FD);

	return 0;
}

sub fuzz_url($;$;$;$)
{
	my $fn     = shift;
	my $method = shift;
	my $path   = shift;
	my $new    = shift;

	# 0 means an error occured that do not
	#         need further processing
	# 1 means the request was somehow successful
	#         and should be further analyzed
	my %fuzz_success =
	(
		500 => 1,	# parsing error leads to internal error
		201 => 1,	# PUT
		200 => 1,	# POST
	);

	print " (url fuzz)\n";
	open my $FD, ">> $fn" or return 1;
	$FD->autoflush(1);
	printf $FD "\n\nTimestamp: %s\n------------------------------\n\n", timestamp();

	# fuzz!
	Fuzz::reset_all();
	$Fuzz::log_fuzz = $cnf_log_fuzz;
	my $iter = 0;
	while(1)
	{
		my $p = $path;
		$iter++;
		my $r = int(rand(1000000));
		$p =~ s/RND/$r/g;
		$p =~ s/INC/$iter/g;

		my ($type, $cnt) = gen_fuzz_url($p, \%Fuzz::h_fuzzconf);

		last unless(defined($type) and defined($cnt)); # no more fuzz strings available

		# 1. HTTP request
		my @rc = http_request_postput($method, $cnt);

		$perf_cnt_url_total++;

		if($cnf_interactive)
		{
			print "\t\tpress RETURN to continue...";
			read STDIN, my $tmp, 1;
		}

		# 2. HTTP response code handling
		unless(defined($fuzz_success{$rc[0]}))
		{
			print "\t\tOutcome: '$rc[1]' -> unknown [$type]\n" unless($cnf_simulate);
			next;
		}
		if($fuzz_success{$rc[0]} == 0)
		{
			my $errdesc = "";
			# some services, like WebYaST, return an error description XXX config?
			$errdesc = ": $1" if($rc[3] =~ /<description>(.*)<\/description>/);
			print "\t\tOutcome: '$rc[1]' -> unhandled, see log files [$type]$errdesc\n" unless($cnf_simulate);
			printf $FD log_str($rc[0], $method, $p, $cnt, $type, $rc[4], 0, ("empty"));
			next;
		}

		# 3. Content-Type checking
		unless($rc[2] =~ /application\/xml/)
		{
			print "\t\tOutcome: '$rc[1]' -> unknown content-type '$rc[2]' [$type]\n" unless($cnf_simulate);
			next;
		}

		# 4. HTTP GET request to get a compareable result
		my @res_get;
		my $path_get = $p;
		if($method eq "POST" and $new) # PUT and some POSTs does not need extra handling
		{
			# this is more tricky because a new entry was created and we
			# do not know the ID directly and the xml tag depends on the
			# implementation :( XXX
			# we can automatically detect it by looking for incrementing
			# integers ot maybe random integers? *phew*
			unless($rc[3] =~ /<id type="integer">(\d+)<\/id>/)
			{
				print "\t\tOutcome: '$rc[1]' -> unable to find ID [$type]\n" unless($cnf_simulate);
				next;
			}
			my $id = $1;
			$path_get =~ s/\.xml$/\/$id\.xml/;
		}
		@res_get = http_request_get($path_get);

		unless($res_get[0] == 200)
		{
			my $errdesc = "";
			# some services, like WebYaST, return an error description XXX config?
			$errdesc = ": $1" if($res_get[3] =~ /<description>(.*)<\/description>/);
			print "\t\tOutcome: '$res_get[1]' -> ERROR for GET $path_get [$type]$errdesc\n";
			next;
		}

		# delete entry if requested
		if($cnf_delete and $new)
		{
			http_request_delete($path_get);
			print "\t\tdeleted created entry\n" if($cnf_debug);
		}


		# 5. Fuzz result analysis XXX
		# look for the fuzzed parameters to occur in the xml and see if they differ
	}
	close($FD);
	return 0;
}

sub log_str($;$;$;$;$;$;$;@)
{
	my $rc = shift;
	my $method = shift;
	my $path = shift;
	my $cnt = shift;
	my $type = shift;
	my $res = shift;
	my $nr_tags = shift;
	my @q = shift;

	$res =~ s/\n/\n\t/g;
	my $log = sprintf("[HDRSTART]\n%s:%s %s %s:%s:\n[HDREND]\n[DATASTART]\n%s\n[DATAEND]\n[TAGSTART]\nentries:%i\n",
		$rc,
		$method,
		$path,
		uri_escape($cnt),
		$type,
		$res,
		$nr_tags);
	$log = $log.$_."\n" foreach(@q);
	$log = $log."[TAGEND]\n\n";

	return $log;
}

sub gen_fuzz_xml($;$)
{
	my $fn = shift;
	my $href_fuzzconf = shift;

	open FD, "$fn";
	my $str_tmpl = "";
	while(<FD>)
	{
		$str_tmpl = sprintf("%s%s", $str_tmpl, $_);
	}
	close FD;

# 	die "str_tmpl: $str_tmpl\n";
	my ($type, $str_fuzz) = gen_fuzz_str($href_fuzzconf);
	if(defined($str_fuzz) and length($str_fuzz) > 0)
	{
		my $r = int(rand(1000000));
		# hm, scape the fuzz string a bit too avoid xml parsing errors and internal errors
		if($cnf_fuzz_dontesc == 0)
		{
			$str_fuzz =~ s/&/&amp;/g;
			$str_fuzz =~ s/</&lt;/g;
			$str_fuzz =~ s/>/&gt;/g;
		}

  		print "str_fuzz xml: '$str_fuzz'\n" if($cnf_log_fuzz);

		$str_tmpl =~ s/RND/$r/g;
		$str_tmpl =~ s/FUZZ/$str_fuzz/g;
	}
	else
	{
		$str_tmpl = undef;
		$type = undef;
	}
	return ($type, $str_tmpl);
}

sub gen_fuzz_url($;$)
{
	my $url = shift;
	my $href_fuzzconf = shift;

	chomp $url;

	my ($type, $str_fuzz) = gen_fuzz_str($href_fuzzconf);
	if(defined($str_fuzz) and length($str_fuzz) > 0)
	{
		my $r = int(rand(1000000));
		# no html escape for url fuzzing of course

 		print "str_fuzz url: '$str_fuzz'\n" if($cnf_log_fuzz);

		$url =~ s/RND/$r/g;
		$url =~ s/FUZZ/$str_fuzz/g;
	}
	else
	{
		$url = undef;
		$type = undef;
	}
	return ($type, $url);
}

sub gen_fuzz_str($)
{
	my $href_fuzzconf = shift;

 	#print Dumper($href_fuzzconf);

	foreach my $k (keys %$href_fuzzconf)
	{
 	#	print "k: ", Dumper($k);
 		print "$k: $href_fuzzconf->{$k}\n" if($cnf_log_fuzz);

		print "TEST: type == 1\n" if($cnf_log_fuzz);
		next if($href_fuzzconf->{$k} == 0);
		print "TEST: func defined\n" if($cnf_log_fuzz);
		next unless(defined($Fuzz::func_tab{$k}));
		print "TEST: more available\n" if($cnf_log_fuzz);
		next if(Fuzz::more_avail($k) == 0);

		my $func = $Fuzz::func_tab{$k};
		my $s = $func->();
		print "\tfuzz str: '$s'\n" if($cnf_log_fuzz);
		return ($k,$s) if(defined($s));
	}
	return (undef, undef);
}

sub http_request_xmlrpc($;$;$)
{

	my $method = shift;
	my $path = shift;
	my $content = shift;

	# brain dead code to build content
	my $cnt_hdr = "------------------------------effc408259be\r\nContent-Disposition: form-data; name=\"new\"; filename=\"x\"\r\nContent-Type: application/octet-stream\r\n";
	my $cnt_tail = "\r\n------------------------------effc408259be--\r\n";
	my $cnt_body = $content;
	$cnt_body =~ s/\n/\r\n/g;
	$content = sprintf("%s\r\n%s\r\n%s", $cnt_hdr, $cnt_body, $cnt_tail);

	my $uri = $cnf_baseurl.$path;

	#$param = uri_escape($param);

	print "\thttp request xmlrpc: $method $uri\n" if($cnf_log_http);

	# Create a request
 	my $req = HTTP::Request->new($method => $uri);

	# build header
	my $h = $cnf_host;
	$h =~ s/:\d+//;
 	$req->header('Accept'=>"*/*");
 	$req->header('Host'=>$h);
 	$req->header('Authorization'=>"Basic ".encode_base64($auth_user.":".$auth_pass));
 	$req->content_type("$cnf_cnt_type;boundary=----------------------------effc408259be"); #text/xml
	$req->content($content);

	print "\trequest: ", Dumper($req->as_string) if($cnf_log_http and $cnf_debug);

	return 0 if($cnf_simulate);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);

	# Check the outcome of the response
	return ($res->code, $res->status_line, $res->header('Content-Type'), $res->content);
}

sub http_request_file($;$;$;$)
{

	my $method    = shift;
	my $path      = shift;
	my $fname     = shift;
	my $fn        = shift;
	my $mime_type = undef;

	$mime_type = mimetype($fname);
	$mime_type = "application/octet-stream" unless(defined($mime_type) or length($mime_type));

	# brain dead code to build content
	my $cnt_hdr = "multipart/form-data;boundary=----------effc408259be";
	my $cnt_body_hdr = "------------effc408259be\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$fn\"\r\nContent-Type: $mime_type\r\n";
	my $cnt_body_tail = "------------effc408259be--\r\n";

	my $b;
	my $content = "";
	open INF, $fname or return 0;
	binmode INF;
	$content = $content.$b while(read(INF, $b, 65536));
	close INF;

	my $cnt_body = $cnt_body_hdr."\r\n".$content."\r\n".$cnt_body_tail;

	my $uri = $cnf_baseurl.$path;

	#$param = uri_escape($param);

	print "\thttp request file: $method $uri <- $fname [$fn] ($mime_type)\n" if($cnf_log_http);

	# Create a request
 	my $req = HTTP::Request->new($method => $uri);

	# build header
	my $h = $cnf_host;
	$h =~ s/:\d+//;
 	$req->header('Accept'=>"*/*");
  	$req->header('Host'=>$h);
 	$req->header('Authorization'=>"Basic ".encode_base64($auth_user.":".$auth_pass));
  	$req->content_type($cnt_hdr);
	$req->content($cnt_body);

	print "\trequest: ", Dumper($req->as_string); # if($cnf_log_http and $cnf_debug);

	return 0 if($cnf_simulate);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);

	# Check the outcome of the response
	return ($res->code, $res->status_line, $res->header('Content-Type'), $res->content);
}

sub http_request_postput($;$)
{

	my $method = shift;
	my $path = shift;
	my $uri = $cnf_baseurl.$path;

	print "\thttp request postput: $method $uri\n" if($cnf_log_http);

	# Create a request
 	my $req = HTTP::Request->new($method => $uri);

	# build header
	my $h = $cnf_host;
	$h =~ s/:\d+//;
 	$req->header('Accept'=>"*/*");
 	$req->header('Host'=>$h);
 	$req->header('Authorization'=>"Basic ".encode_base64($auth_user.":".$auth_pass));
 	#$req->content_type($cnf_cnt_type); #text/xml

	print "\trequest: ", Dumper($req->as_string) if($cnf_log_http and $cnf_debug);

	return 0 if($cnf_simulate);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	return ($res->code, $res->status_line, $res->header('Content-Type'), $res->content);
}

sub http_request_get($)
{
	http_request("GET", shift);
}

sub http_request_delete($)
{
	http_request("DELETE", shift);
}

sub http_request($;$)
{
	my $method = shift;
	my $path = shift;

	my $uri = $cnf_baseurl.$path;

	print "\thttp request: $method $uri\n" if($cnf_log_http);

	# Create a request
	my $req = HTTP::Request->new($method => $uri);

	# build header
	$req->header('Accept'=>"*/*");
	$req->header('Host'=>$cnf_host);
	$req->header('Authorization'=>"Basic ".encode_base64($auth_user.":".$auth_pass));

	return 0 if($cnf_simulate);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);

	# Check the outcome of the response
	return ($res->code, $res->status_line, $res->header('Content-Type'), $res->content);
}

sub xml2param($)
{
	my $href_xml = shift;
	my $str = "";

	# we need two levels of nesting, exactly two!
	foreach my $key_1 (keys %$href_xml)
	{
		next unless(defined(keys %{$href_xml->{$key_1}}));
		for my $key_2 (keys %{$href_xml->{$key_1}})
		{
			$str = sprintf("%s&%s[%s]=%s", $str, $key_1, $key_2, $href_xml->{$key_1}->{$key_2});
		}
	}
	$str =~ s/^&//;
	return $str;
}

sub xml2str_crawl($;$)
{
	my $href_xml = shift;
	my $key = shift;
	my $k = $key;
	my $v = $href_xml->{$key};

	print 'ref($href_xml) :', ref($href_xml), "\n";

	return ($k, $v) unless ref($href_xml) eq 'HASH';

	return ($k, $v);
}

sub xml2str($)
{
	my $href_xml = shift;
	my $str = "";

	print Dumper($href_xml);

	# we need at least two levels of nesting (root + others)
	foreach my $key_1 (keys %$href_xml)
	{
		$str = "<$key_1>";
		next unless(defined(keys %{$href_xml->{$key_1}}));
		for my $key_2 (keys %{$href_xml->{$key_1}})
		{
# 			my($k, $v) = xml2str_crawl($href_xml->{$key_1}, $key_2);
# 			print "k = $k, v = $v, href_xml->{$key_1} = $key_2\n";
# 			last unless defined($k) and defined($v);
			$str = sprintf("%s\n<%s>%s</%s>", $str, $key_2, $href_xml->{$key_1}->{$key_2}, $key_2);
		}
		$str = sprintf("%s\n</%s>", $str, $key_1);
	}
	return $str;
	#return XMLout($href_xml, RootName => $key_1, NoEscape => 1);
}

sub what_method($)
{
	my $m = shift;

	my %h = (
		"DELETE"=>0,
		"GET"=>0,
		"PUT"=>1,
		"POST"=>1
		);

	return $h{$m} if(defined($h{$m}));
	return -1;
}

sub parse_targetlist($)
{
	my $fn = shift;
	my %h = ();

	open FD, "< ".$fn || die("Error: Unable to read file $fn\n");
	while(<FD>)
	{
		next if(/^#.*/);
		print;
		next unless(/(\w+)\s+([\w\d.\/\&\?\=\-]+)\s+([\w\d.\/\-]+)\s+(\w+)\s*([\w\/\+\-\d]*)/);
		my $template	= $3;
		my $path	= $2;
		my $method	= $1;
		$method		=~ tr/a-z/A-Z/;
		my $makenew	= 0;
		$makenew	= 1 if($4 =~ /^new$/i);
		$cnf_cnt_type	= $5 if(defined($5) and length($5) > 0);


		$h{$path}{$method}{"tmpl"} = $template;
		$h{$path}{$method}{"new"}  = $makenew;
		#what_method($method);
		#$h{$path}{'template'} = $template;
	}
	close FD;

	return %h;
}

sub test($)
{
	my $t = shift;
	my %ht = %$t;

	#print Dumper(%ht);

	# uh, brain dead
	foreach my $path (keys %ht)
	{
		foreach my $hm ($ht{$path})
		{
			foreach my $method (keys %$hm)
			{
				my @rc = http_request("GET", $path);
				print "\t\t", Dumper(@rc), "\n";
			}
		}

	}


}

my $timestamp_first = undef;
sub timestamp()
{
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

	return sprintf("%04s-%02s-%02s_%02s%02s%02s", $year+1900, $mon+1, $mday, $hour, $min, $sec);
}

