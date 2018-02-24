#!/usr/bin/perl -w

use strict;
use utf8;

use Time::Local;
use File::Basename;
use File::Find;
use Data::Dumper;
use URI::Escape;

#use MyUtils;

my $package_url = "http://gitorious.org/code-scanner/ror-sec-scanner/";

# configs
our $conf_dir         = ".";
our $conf_noinfo      = 0;
our $conf_nolow       = 0;
our $conf_nomedium    = 0;
our $conf_nohigh      = 0;
our $conf_ignkeyword  = 0;
our $conf_reducepath  = 1;
# our $conf_filelist    = "filelist.txt";
# our $conf_xcld_file   = "exclude-files.txt";
# our $conf_icld_file   = "include-files.txt";
our $conf_rulesdir    = "rules/";
our $conf_output_html = 0;

# files
our @filelist = ();
our @filelist_views = ();
our @filelist_models = ();
our @filelist_controllers = ();
our @filelist_config = ();
our @ruleslist = ();

# rules
our $href_rules = ();
our $rules_total = 0;
our @rules_xcld = ();
our @rules_icld = ();

# stats
our $stat_lines_total = 0;
our $stat_lines_ignored = 0;
our $stat_sloc	= 0;
our $stat_ksloc	= 0;
our $stat_hits_total  = 0;
our $stat_hits_low    = 0;
our $stat_hits_medium = 0;
our $stat_hits_high   = 0;
our $stat_hits_info   = 0;
our $stat_files_ignored = 0;

our $today = localtime();


#
# util functions
#
sub html_escape($)
{
	my $l = shift;
	$l =~ s/&/&amp;/g;
	$l =~ s/</&lt;/g;
	$l =~ s/>/&gt;/g;
	return $l;
}

sub unique(@)
{
	my @a = @_;
	my @b;
	my $first;
	my $last;
	my $current;


	$last = $first = shift(@a);

	foreach $current (@a)
	{
		unless($last eq $current)
		{
			push(@b, $current);
			$last = $current;
		}
	}

	unshift(@b, $first);

	return @b;
}

#
# output functions
#
sub output_header()
{
	if($conf_output_html)
	{
		printf("<html>\n<head><title>RoR Code Scan of \"%s\"</title></head><body>\n", $conf_dir);
		printf("<p>Generated using %s</p>\n", $package_url);

	}
}

sub output_tail()
{
	if($conf_output_html)
	{
		printf("</body>\n</html>\n");
	}
}

sub output_config()
{
	if($conf_output_html)
	{
		printf "<h1>Configuration</h1>";

		printf "<table width='70%%' border='1'>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>date:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $today;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>rules dir:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $conf_rulesdir;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>ignore info rules:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $conf_noinfo ? "yes" : "no";
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>ignore low rules:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $conf_nolow ? "yes" : "no";
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>ignore medium rules:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $conf_nomedium ? "yes" : "no";
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>ignore high rules:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</td>\n", $conf_nohigh ? "yes" : "no";
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of rules files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</td>\n", $#ruleslist+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of rules loaded:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</td>\n", $rules_total;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>xcld rules loaded:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</td>\n", $#rules_xcld+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>icld rules loaded:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</td>\n", $#rules_icld+1;
		printf "\t</tr>\n";

		printf "</table>\n";

		printf "<p>\n";

		printf "<table width='70%%' border='1'>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>search dir:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</font></td>\n", $conf_dir;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>reduce path:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%s</font></td>\n", $conf_reducepath ? "yes" : "no";;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of code files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $#filelist+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of views files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $#filelist_views+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of modell files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $#filelist_models+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of controller files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $#filelist_controllers+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><font size=\"-1\"><b>nr. of config files:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $#filelist_config+1;
		printf "\t</tr>\n";

		printf "</table><p>\n";
	}
	else
	{
		printf "date:			%s\n\n", $today;
		printf "rules dir:		%s\n",   $conf_rulesdir;
		printf "ignore info:		%s\n",   $conf_noinfo   ? "yes" : "no";
		printf "ignore low:		%s\n",   $conf_nolow    ? "yes" : "no";
		printf "ignore medium:		%s\n",   $conf_nomedium ? "yes" : "no";
		printf "ignore high:		%s\n",   $conf_nohigh   ? "yes" : "no";
		printf "no rule files:		%i\n",   $#ruleslist+1;
		printf "rules loaded:		%i\n\n", $rules_total;
		printf "xcld rules loaded:	%i\n",   $#rules_xcld+1;
		printf "icld rules loaded:	%i\n",   $#rules_icld+1;
		printf "search dir:		%s\n",   $conf_dir;
		printf "reduce path:		%s\n",   $conf_reducepath ? "yes" : "no";
		printf "no code files:		%i\n",   $#filelist+1;
		printf "no view files:		%i\n",   $#filelist_views+1;
		printf "no models files:	%i\n",   $#filelist_models+1;
		printf "no controller files:	%i\n",   $#filelist_controllers+1;
		printf "no config files:	%i\n\n", $#filelist_config+1;
	}
}

sub output_stat() # fix for noXXX switch
{
	if($conf_output_html)
	{
		printf "<h1>Statistics</h1>";

		printf "<table width='70%%' border='1'>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Lines ignored by keyword:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $stat_lines_ignored;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Files ignored by keyword:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $stat_files_ignored;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Lines analyzed:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $stat_lines_total;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Physical Source Lines of Code (SLOC):</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">%i</font></td>\n", $stat_sloc;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Hits\@level:</b></font></td>\n";
		printf "\t\t<td><font size=\"-1\">[<font color='#0000FF'>info</font>] %i [<font color='#00AA000'>low</font>] %i [<font color='#FFAA00'>medium</font>] %i [<font color='#FF0000'>high</font>] %i</font></td>\n",
			$stat_hits_info, $stat_hits_low, $stat_hits_medium, $stat_hits_high;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td><font size=\"-1\"><b>Hits/KSLOC\@level+ (KLSOC = %i):</b></font></td>\n", $stat_ksloc;
		printf "\t\t<td><font size=\"-1\">[<font color='#0000FF'>info+</font>] %i [<font color='#00AA000'>low+</font>] %i [<font color='#FFAA00'>medium+</font>] %i [<font color='#FF0000'>high+</font>] %i</font></td>\n",
			($stat_hits_total)/$stat_ksloc,
			($stat_hits_low+$stat_hits_medium+$stat_hits_high)/$stat_ksloc,
			($stat_hits_medium+$stat_hits_high)/$stat_ksloc,
			($stat_hits_high)/$stat_ksloc;
		printf "\t</tr>\n";

		printf "</table>\n";
	}
	else
	{
		printf "\nLines ignored by keyword = %i\n",
			$stat_lines_ignored;
		printf "\nFiles ignored by keyword = %i\n",
			$stat_files_ignored;
		printf "\nHits = %i\n",
			$stat_hits_total;
		printf "Lines analyzed = %i\n",
			$stat_lines_total;
		printf "Physical Source Lines of Code (SLOC) = %i\n",
			$stat_sloc;
		printf "Hits\@level = [info] %i [low] %i [medium] %i [high] %i\n",
			$stat_hits_info, $stat_hits_low, $stat_hits_medium, $stat_hits_high;
		printf "Hits/KSLOC\@level+ = [info+] %f [low+] %f [medium+] %f [high+] %f\n\n",
			($stat_hits_total)/$stat_ksloc,
			($stat_hits_low+$stat_hits_medium+$stat_hits_high)/$stat_ksloc,
			($stat_hits_medium+$stat_hits_high)/$stat_ksloc,
			($stat_hits_high)/$stat_ksloc;
	}
}

sub output_line($;$;$;$;$) # XXX html escape lines
{
	my $fn = shift;
	my $ln = shift;
	my $rc = shift;
	my $rule_file = shift;
	my $l = shift;

	if($conf_output_html)
	{
		my $impact = $href_rules->{$rule_file}->{$rc}->{"impact"};
		my $color = "#0000FF";
		$color = "#00AA00" if($impact =~ /low/i);
		$color = "#FFAA00" if($impact =~ /medium/i);
		$color = "#FF0000" if($impact =~ /high/i);

		my $cwe = $href_rules->{$rule_file}->{$rc}->{"cwe"};
		my @cwe_list = split ',', $cwe;
		my $cwe_url_list = "";
		foreach my $c (@cwe_list)
		{
			next unless($c =~ /CWE\-(\d+)/);
			my $n = $1;
			$cwe_url_list =
				sprintf("%s,<a href='http://cwe.mitre.org/data/definitions/%i.html' target='_blank'>%s</a>",
				$cwe_url_list, $n, $c);
		}
		$cwe_url_list =~ s/^,//;

		printf "<li>%s:%i [<font color='%s'>%s:%s:rule %i:<b>%s</b>:%s</font>]\n\t<pre>\n\t%s\n\t</pre><br>\n",
			$fn, $ln, $color,
			$rule_file, $href_rules->{$rule_file}->{"desc"},
			$rc,
			$impact,
			$cwe_url_list,
			#uri_escape($l);
			html_escape($l);
	}
	else
	{
		printf "%s:%i [%s:%s:rule %i:%s:%s]\n\t%s\n\n",
			$fn, $ln,
			$rule_file, $href_rules->{$rule_file}->{"desc"},
			$rc,
			$href_rules->{$rule_file}->{$rc}->{"impact"},
			$href_rules->{$rule_file}->{$rc}->{"cwe"},
			$l;
	}
}

#
# sub routines
#
sub analyse_file($;$)
{
	my $basedir = shift;
	my $fn = shift;
	
	open FD, "< ".$basedir."/".$fn or return 1;

	my $kw_ign_nxt_line = 0;
	my $ln = 0;
	while(<FD>)
	{
		$ln++;
		$stat_lines_total++;

		# trim line
		my $l = $_;
		chomp $l;
		$l =~ s/^\s*//;

		# SLOC
 		next unless(length($l)); # empty line
   		next if( ($l =~ /^[\s\t]*#/) and not ($l =~ /RORSCAN_/)); # only a comment, except the one with keywords
		$stat_sloc++;

		# in code keyword handling
		unless($conf_ignkeyword)
		{
			if($l =~ /RORSCAN_ICF/i) # ignore complete file
			{
				$stat_files_ignored++;
				last;
			}
			next if($l =~ /RORSCAN_ITL/i); # ignore this line
# 			next if($conf_noinfo and $l =~ /XXX tom/i); # XXX thake care here
			if($kw_ign_nxt_line > 0)
			{
				$kw_ign_nxt_line--;
				$stat_lines_ignored++;
				next;
			}
			if($l =~ /RORSCAN_INL_(\d+)/i) # ignore next n lines
			{
				$kw_ign_nxt_line = $1;
				next;
			}
			if($l =~ /RORSCAN_INL/i) # ignore next line
			{
				$kw_ign_nxt_line = 1;
				next;
			}
		}

		next if($l =~ /^def\s+/); # we ignore method definitions

		#
		# MATCH RULE
		#
		foreach my $rule_file (keys %$href_rules)
		{
			for(my $rc = 1; $rc <= $href_rules->{$rule_file}->{"max"}; $rc++)
			{
				next unless $l =~ /$href_rules->{$rule_file}->{$rc}->{"regex"}/; # XXX tom: should we limit our rules and stop at a beginning comment?
				$stat_hits_total++;
				$stat_hits_high++   if($href_rules->{$rule_file}->{$rc}->{"impact"} =~ /high/i);
				$stat_hits_medium++ if($href_rules->{$rule_file}->{$rc}->{"impact"} =~ /medium/i);
				$stat_hits_low++    if($href_rules->{$rule_file}->{$rc}->{"impact"} =~ /low/i);
				$stat_hits_info++   if($href_rules->{$rule_file}->{$rc}->{"impact"} =~ /info/i);

				output_line($fn, $ln, $rc, $rule_file, $l);
			}
		}
	}
	close FD;
	
	return 1
}

sub reduce_path(@)
{
	my $p = shift;

	my @ps = split '/', @$p;

	my $min_eq_len = $#ps+1;

	foreach my $pp (@$p)
	{
		my @pps = split '/', $pp;
		my $eq_len = 0;

		foreach my $tmp (@pps)
		{
			last unless($tmp eq $ps[$eq_len]);
			$eq_len++;
		}
		$min_eq_len = $eq_len if($eq_len < $min_eq_len);
	}

	my $cnt = 0;
	foreach my $pp (@$p)
	{
		my @pps = split '/', $pp;
		my @new = ();
		for(my $i = $min_eq_len; $i <= $#pps; $i++)
		{
			push @new, $pps[$i];
		}

# 		${@$p[$cnt]}[0] = join '/', @new;
		$cnt++;
	}
}

sub wanted_source()
{
	return unless /\.(erb|rb|rhtml)$/i;
	my $fn = $File::Find::name;
	$fn =~ s/^$conf_dir// if($conf_reducepath);

	# include and exclude filtering (note we work on the reduced pathname)
	# 1. icld
	foreach my $icld (@rules_icld)
	{
		next unless defined($icld);
		next unless length($icld);
		return unless $fn =~ /$icld/;
	}
	# 2. xcld
	foreach my $xcld (@rules_xcld)
	{
		next unless defined($xcld);
		next unless length($xcld);
		return if $fn =~ /$xcld/;
	}

	push @filelist, $fn;
	if($fn =~ /\/app\/views\//)
	{
		push @filelist_views, $fn;
	}
	elsif($fn =~ /\/app\/models\//)
	{
		push @filelist_models, $fn;
	}
	elsif($fn =~ /\/app\/controllers\//)
	{
		push @filelist_controllers, $fn;
	}
	elsif($fn =~ /\/config\/environment\.rb$/)
	{
		push @filelist_config, $fn;
	}

}
sub create_filelist($)
{
	find \&wanted_source, shift;
	@filelist	     = sort @filelist;
	@filelist_config      = sort @filelist_config;
	@filelist_controllers = sort @filelist_controllers;
	@filelist_models      = sort @filelist_models;
	@filelist_views       = sort @filelist_views
}

sub wanted_rules()
{
	return unless /^\d+_.*\.rule/;
	my $fn = $File::Find::name;
	$fn =~ s/^$conf_rulesdir// if($conf_reducepath);
	push @ruleslist, $fn;
}
sub create_ruleslist($)
{
	find \&wanted_rules, shift;
	@ruleslist = sort @ruleslist;
}

sub parse_rules()
{
	foreach my $rf (@ruleslist)
	{
		open FD, "<".$conf_rulesdir."/".$rf or next;
		my $cnt = 0;
		my $rc = 1; # rule counter
		$href_rules->{$rf}->{"max"} = 0;
		while(<FD>)
		{
			my $l = $_;

			$cnt++;

			next if($l =~ /^#/);
			next if($l =~ /^[\t\s]*$/);

			# the description
			if($l =~ /^Desc:\s*(.*)/)
			{
				$href_rules->{$rf}->{"desc"} = $1;
				next;
			}
			# the rule
			if($l =~ /^(\w+)[\s\t]+([\w,\d\-]+)[\s\t]+(.+)/)
			{
				my $impact = $1;
				my $cwe = $2;
				my $regex = $3;

				next if($impact =~ /^info$/i   and $conf_noinfo);
				next if($impact =~ /^low$/i    and $conf_nolow);
				next if($impact =~ /^medium$/i and $conf_nomedium);
				next if($impact =~ /^high$/i   and $conf_nohigh);

				$href_rules->{$rf}->{$rc}->{"impact"}	= $impact;
				$href_rules->{$rf}->{$rc}->{"cwe"} 	= $cwe;
				$href_rules->{$rf}->{$rc}->{"regex"}	= $regex;

				$href_rules->{$rf}->{"max"}	     = $rc;
				$rules_total++;
				$rc++;
			}
			else
			{
				print "$rf:$cnt parsing error\n";
			}
		}
		close FD;
	}
}


#
# Main
#

# argv
foreach my $arg (@ARGV)
{
	if($arg =~ /--help/ or $arg =~ /-h/)
	{
		print "usage: main.pl\n";
		print "\t[-h|--help] [output=(html|ascii)]]\n";
		print "\t[no(info|low|medium|high|keyword)]\n";
		print "\t[(icld|xcld)pat=<regex>]\n";
		print "\t[(icld|xcld)file=<filename>]\n";
		print "\tdir=<dir>\n";
		exit 0;
	}

	$conf_dir	  = $1 if $arg =~ /^dir=(.*)/i;
	$conf_noinfo      = 1  if $arg =~ /^noinfo$/i;
	$conf_nolow       = 1  if $arg =~ /^nolow$/i;
	$conf_nomedium    = 1  if $arg =~ /^nomedium$/i;
	$conf_nohigh      = 1  if $arg =~ /^nohigh$/i;
	$conf_ignkeyword  = 1  if $arg =~ /^ignkeyword$/i;
	$conf_reducepath  = 1  if $arg =~ /^rpath$/i;
	$conf_output_html = 1  if $arg =~ /^output=html$/i;
	push @rules_xcld, $1   if $arg =~ /^xcldpat=(.*)/i;
	push @rules_icld, $1   if $arg =~ /^icldpat=(.*)/i;

	if($arg =~ /^xcldfile=(.*)/i)
	{
		my $fn = $1;
		open FD, "< ".$fn or die("unable to open xcldfile $fn.");
		while(<FD>)
		{
			chomp;
			push @rules_xcld, $_;
		}
		close FD;
	}
	if($arg =~ /^icldfile=(.*)/i)
	{
		my $fn = $1;
		open FD, "< ".$fn or die("unable to open icldfile $fn.");
		while(<FD>)
		{
			chomp;
			push @rules_icld, $_;
		}
		close FD;
	}
}
die("error: $conf_dir invalid") unless -d $conf_dir;
die("Really ignore everything?!? Nothing to do then...") if($conf_nohigh and $conf_nomedium and $conf_nolow and $conf_noinfo);


# sort and unify the include and exclude rules
@rules_xcld = unique(sort @rules_xcld);
@rules_icld = unique(sort @rules_icld);


# print header
output_header();


# create file and rule list
create_filelist($conf_dir);
create_ruleslist($conf_rulesdir);


# parse rules
parse_rules();


# print config etc.
output_config();


# analyse files
foreach my $fn (@filelist)
{
	analyse_file($conf_dir, $fn);
}


# print stats
$stat_ksloc = $stat_sloc / 1000;
output_stat();

# print tail
output_tail();

exit 0;

