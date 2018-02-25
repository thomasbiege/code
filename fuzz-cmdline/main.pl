#!/usr/bin/perl -w

#use strict;
use utf8;

use Time::HiRes qw( usleep nanosleep );
use POSIX ":sys_wait_h";
use File::Basename;
use Data::Dumper;

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

# globals
our $execution_interrupted = 0;


# performance stuff
our $pf_starttime = 0;
our $pf_endtime   = 0;
our $pf_execcnt   = 0;
our $pf_crashcnt  = 0;

# session stuff
#FD_SESS;

# global config options
our $conf_fn_config  = "config.txt";
our $conf_fn_pattern = "pattern-file.txt";
our $conf_fn_lastrun = "lastrun.txt";
our $conf_fn_log     = "crash-log.txt";
our $conf_cmd        = "";
our $conf_reload     = 0;
our @conf_scr_pre    = ();
our @conf_scr_post   = ();
our @conf_scr_init   = ();

our $today           = localtime();

#our @fuzz_types      = keys %Fuzz::h_fuzzconf;
our @fuzz_types      = ("int32", "uint32", "bof",
			"shell", "fmt", "sep", "sql", "ldap", "eol",
			"html", "perl");
our $flag_fuzz_int32  = 0;
our $flag_fuzz_int64  = 0;
our $flag_fuzz_uint32 = 0;
our $flag_fuzz_uint64 = 0;
our $flag_fuzz_bof    = 0;
our $flag_fuzz_shell  = 0;
our $flag_fuzz_fmt    = 0;
our $flag_fuzz_sep    = 0;
our $flag_fuzz_sql    = 0;
our $flag_fuzz_ldap   = 0;
our $flag_fuzz_eol    = 0;
our $flag_fuzz_html   = 0;
our $flag_fuzz_perl   = 0;

our $cmdstr       = "";
our @cmdstr_array = ();
our @optarray     = ();
our $optarray_len = 0;


# signals
our $timeout_flag  = 0;
our $timeout_delay = 5;
our $signal_flag   = 0;

$SIG{ALRM}   = 'timeout_clock';

$SIG{INT}    = 'signal_int';
$SIG{KILL}   = 'signal_int';
$SIG{QUIT}   = 'signal_int';
$SIG{TERM}   = 'signal_int';

$SIG{SEGV}   = 'signal_watch';
$SIG{ILL}    = 'signal_watch';
$SIG{ABRT}   = 'signal_watch';
$SIG{FPE}    = 'signal_watch';
$SIG{STKFLT} = 'signal_watch';
$SIG{IO}     = 'signal_watch';
$SIG{XCPU}   = 'signal_watch';
$SIG{XFSZ}   = 'signal_watch';

sub signal_watch($)
{
	my $signum = shift;
	print "signal reveived: $signum\n";
	$signal_flag = 1;
}

sub signal_int($)
{
	$execution_interrupted = 1;
}

sub timeout_clock($)
{
	$timeout_flag = 1;
}


sub exec_and_watch($)
{
	my $cmd = shift;
	my $child_pid = undef;
	
	if(!defined($child_pid = fork()))
	{
		print "cannot fork... continue.\n";
		return -1;
	}

	if($child_pid == 0)
	{
		#print "execute: $cmd\n";
		exec(split / /, $cmd) or print "unable to execute command: $cmd -> $!\n";
		#exit -1;
	}

	my $signal_flag = 0;
	my $timeout_flag = 0;
	alarm($timeout_delay);

	while(1)
	{
		my $rv = waitpid($child_pid, WNOHANG);

		if($rv == $child_pid)
		{
			print "waitpid() return status: $?\n";

			return 0 if($? == 0 || $? == 2); # 2 -> interrupt from keyb: ctrl+c
			return 1;
		}

		if($rv == 0) # child still running
		{
			$rv = kill(0, $child_pid); # does not work if UID changed :-(
			if($rv != 1)
			{
				waitpid($child_pid, WNOHANG);
				print "kill() was unable to send signal 0\n";
				return 1;
			}
		}

		if($timeout_flag == 1)
		{
			kill(9, $child_pid);
			waitpid($child_pid, WNOHANG);
			print "timeout has occured\n";
			return 1;
		}

		if($signal_flag == 1)
		{
			waitpid($child_pid, WNOHANG);
			print "child received a signal\n";
			return 1;
		}

		if($execution_interrupted == 1)
		{
			kill(9,$child_pid);
			waitpid($child_pid, WNOHANG);
			return -1;
		}

		usleep(100);

		$signal_flag = 0;
		$timeout_flag = 0; # XXX: really needed after a sleep()? also dangerous -> race cond.
	}

	#waitpid($child_pid, WNOHANG);

	return 0; 
}

sub parse_config($)
{
	my $fn = shift;

	open(FD, "<".$fn) || die("Unable to open $fn");

	my $i = 1;
	while(<FD>)
	{
		next if(/^#/);
		$conf_fn_lastrun =              $1 if(/lastrun=(.*)/i);
		$conf_fn_pattern =              $1 if(/pattern=(.*)/i);
		$conf_fn_log     =              $1 if(/crashlog=(.*)/i);
		$conf_cmd        =              $1 if(/cmd=(.*)/i);
		@conf_scr_init   = split /\s+/, $1 if(/initscript=(.*)/i);
		@conf_scr_pre    = split /\s+/, $1 if(/prescript=(.*)/i);
		@conf_scr_post   = split /\s+/, $1 if(/postscript=(.*)/i);
		$timeout_delay   =              $1 if(/timeout=(\d+)/i);
	}
	close(FD);
}

sub parse_patternfile($)
{
	my $fn = shift;
	my $cmd = undef;
	
	open(FD, "<".$fn) || die("Unable to open $fn");
	die("Unable to read command-name from $fn") unless(defined($cmd = <FD>) );
	chomp($cmd);
	#$cmdstr = "gdb -q -batch -x ./gdb-batch.txt --args " . $cmd;
	$cmdstr = $cmd;
	push @cmdstr_array, $cmd;

	my $i = 0;
	while(<FD>)
	{
		next if(/^#/);
		
		my $optstr = $_;
		chomp($optstr);

		unless($optstr =~ /\:/)
		{
			print "line format is invalid... skipping this line: '$_'\n";
			next;
		}

		my $cnt = 0;
		my($o, @v) = split /:/, $optstr;
		if(defined($o)) # option name
		{
			$cmdstr = sprintf("%s %s ", $cmdstr, $o); 
			$optarray[$i][$cnt] = $o;
			$cnt++;
		}
		push(@cmdstr_array, $o) if(length($o) > 0);
		foreach(@v) # option value
		{
			chomp;
			next unless length $_; 
			push(@cmdstr_array, $_);
			$cmdstr = sprintf("%s%s:", $cmdstr, $_); # XXX bad solution for : in option value
			$optarray[$i][$cnt] = $_;
			$cnt++;
			$flag_fuzz_int32  = 1 if(/FUZZINT32/);
			$flag_fuzz_int64  = 1 if(/FUZZINT64/);
			$flag_fuzz_uint32 = 1 if(/FUZZUINT32/);
			$flag_fuzz_uint64 = 1 if(/FUZZUINT64/);
			$flag_fuzz_bof    = 1 if(/FUZZBOF/);
			$flag_fuzz_shell  = 1 if(/FUZZSHELL/);
			$flag_fuzz_fmt    = 1 if(/FUZZFMT/);
			$flag_fuzz_sep    = 1 if(/FUZZSEP/);
			$flag_fuzz_sql    = 1 if(/FUZZSQL/);
			$flag_fuzz_eol    = 1 if(/FUZZEOL/);
			$flag_fuzz_ldap   = 1 if(/FUZZLDAP/);
			$flag_fuzz_perl   = 1 if(/FUZZPERL/);
			$flag_fuzz_html   = 1 if(/FUZZHTML/);
		}
		$cmdstr =~ s/:$//;
		#print "cmdstr_array: ", Dumper(@cmdstr_array);
		$i++;
	}
	close(FD);

	$optarray_len = $i - 1;
	#print "XXX cmdstr_array:\n", Dumper(@cmdstr_array);

	$cmdstr =~ s/  / /g;
	print "command string: $cmdstr\n";
	#print Dumper(@optarray);
}

sub sess_start()
{
	open(FD_SESS, ">".$conf_fn_lastrun) || die("Unable to open $conf_fn_lastrun\n");
	open(FD_LOG, ">>".$conf_fn_log)     || die("Unable to open $conf_fn_log\n");
	print FD_LOG "\n[$today] CMD: $cmdstr\n"
}

sub sess_update($)
{
	my $cs = shift;

	# XXX parse $cmdstr with @optarry
	my @cs_splitted = split(/ /,$cs);
	shift(@cs_splitted);

	truncate(FD_SESS, 0);
	seek(FD_SESS, 0, 0);

	for(my $j = 0; $j < $#cs_splitted; $j++)
	{
		my $arg = $cs_splitted[$j];

		#print "\t" . "arg: " . $arg . "\n";

		for(my $i = 0; $i < $optarray_len; $i++)
		{
			next unless(defined($optarray[$i]));
			next unless(defined($optarray[$i][0]));
			#next unless(length($optarray[$i][0]) > 0);

			if($arg =~ /$optarray[$i][0]/) # found and opt switch
			{
				next unless(defined($optarray[$i][1]));

				my $valtype = $optarray[$i][1];
				$j++;

				#print "\t" . $valtype . " -> " . $cs_splitted[$j] . "\n";

				# check value and write it to lastrun file
				if($valtype =~ /len32/)
				{
					print FD_SESS
						$arg . ":" . $valtype . ":" .
						$inc_start . ":" . $inc_end . ":" . $inc_step . ":" .
						$cs_splitted[$j] . "\n";
				}
				elsif($valtype =~ /stringascii/)
				{
					print FD_SESS
						$arg . ":" . $valtype . ":" .
						$rep_char . ":" . $rep_start . ":" . $rep_end . ":" .
						length($cs_splitted[$j]) . "\n";
				}
				elsif($valtype =~ /stringbin/)
				{
					print FD_SESS
						$arg . ":" . $valtype . ":" .$pat_start . ":" . $pat_end . ":" .
						length($cs_splitted[$j]) . "\n";
				}
				elsif($valtype =~ /\w*#\w+#\w*/)
				{
					# no session saving for shell meta chars
				}

			}
		}
	}

	#FD_SESS "EOR\n";
}

sub sess_init()
{
	my $rv = 0;

	unless(open(FD, "<".$conf_fn_lastrun))
	{
		print "Unable to open $conf_fn_lastrun\n";
		return $rv;
	}
	
	while(<FD>)
	{
		chomp;
		my @sessstr = split(/:/, $_);

		unless(defined($sessstr[0]))
		{
			$rv = -1;
			last;
		}
		if($#sessstr < 2)
		{
			$rv = -1;
			last;
		}

		my $valtype = $sessstr[1];
		# XXX verify if this valtype and arg switch are in @optarray

		#print "\nsession string [$#sessstr]:\n";
		#foreach(@sessstr)
		#{
		#	print "\t" . $_ . "\n";
		#}
		#print "\nvaltype:\n";
		#print $valtype . "\n";

		if($valtype =~ /len32/)
		{
			if($#sessstr != 5)
			{
				$rv = -2;
				last;
			}

			$inc_start = $sessstr[2];
			$inc_end   = $sessstr[5];
			$inc_step  = $sessstr[4];
		}
		elsif($valtype =~ /stringascii/)
		{
			if($#sessstr != 5)
			{
				$rv = -2;
				last;
			}

			$rep_char  = $sessstr[2];
			$rep_start = $sessstr[3];
			$rep_end   = $sessstr[5];
		}
		elsif($valtype =~ /stringbin/)
		{
			$rv = -2;
		}
		else
		{
			# XXX valtype unknown
			$rv = -3;
		}
		
	}
	close FD;

	return $rv;
}

sub sess_end()
{
	close(FD_SESS);
	close(FD_LOG);
}


sub perf_start()
{
	$pf_execcnt = 0;
	$pf_starttime = time();
}

sub perf_update()
{
	$pf_execcnt++;
}

sub perf_update_crash()
{
	$pf_crashcnt++;
}

sub perf_end()
{
	$pf_endtime = time();

	my $pf_difftime = $pf_endtime - $pf_starttime;
	$pf_difftime = 1 unless($pf_difftime);
	my $pf_execpersec = int($pf_execcnt / $pf_difftime);

	print "\n\ncalled command $pf_execcnt times with $pf_crashcnt crashes in $pf_difftime secs -> ~$pf_execpersec/sec\n\n";
}

sub run_prog($)
{
	my $cs = shift;
	
	print "\tcmd: $cs\n";

	sess_update($cs);
	perf_update(); # XXX: not the perfect place b/c child may fail
	my $rv = exec_and_watch($cs);

	if($rv == -1)
	{
		#print "\n\terror ocurred while executing chlid.";
		last if($execution_interrupted == 0);

		print "\n\tinterrupted by user...\n\n";

		perf_end();
		sess_end();

		exit -1;
	}
	#elsif($rv == 0)
	#{
	#       print "\n\tchild exited normally.\n\n";
	#}
		elsif($rv == 1)
	{
		print FD_LOG "$cs\n";
		print "\n\tCHILD DID NOT RESPOND, CRASHED OR EXITED ABNORMALY!\n\n";
		perf_update_crash();
		sleep(1);
	}
}

sub gen_fuzz(@)
{
	my @str_tmpl = @_;
	
	my $href_fuzz = gen_fuzz_str();
# 	print "XXX href_fuzz:\n", Dumper($href_fuzz);
# 	print "XXX str_tmpl:\n", Dumper(@str_tmpl);
	return undef if($href_fuzz->{done});
	my $r = int(rand(1000000));
	for(my $i = 0; $i <= $#str_tmpl; $i++)
	{
		#print "\tstr_tmpl[$i]: $str_tmpl[$i]\n";
		next unless($str_tmpl[$i] =~ /(FUZZ|RND)/);
		$str_tmpl[$i] =~ s/FUZZINT32/$href_fuzz->{"int32"}/g if(defined($href_fuzz->{"int32"}));
		$str_tmpl[$i] =~ s/FUZZUINT32/$href_fuzz->{"uint32"}/g if(defined($href_fuzz->{"uint32"}));
		$str_tmpl[$i] =~ s/FUZZBOF/$href_fuzz->{"bof"}/g     if(defined($href_fuzz->{"bof"}));
		$str_tmpl[$i] =~ s/FUZZSHELL/$href_fuzz->{"shell"}/g if(defined($href_fuzz->{"shell"}));
		$str_tmpl[$i] =~ s/FUZZFMT/$href_fuzz->{"fmt"}/g     if(defined($href_fuzz->{"fmt"}));
		$str_tmpl[$i] =~ s/FUZZSEP/$href_fuzz->{"sep"}/g     if(defined($href_fuzz->{"sep"}));
		$str_tmpl[$i] =~ s/FUZZSQL/$href_fuzz->{"sql"}/g     if(defined($href_fuzz->{"sql"}));
		$str_tmpl[$i] =~ s/FUZZEOL/$href_fuzz->{"eol"}/g     if(defined($href_fuzz->{"eol"}));
		$str_tmpl[$i] =~ s/FUZZLDAP/$href_fuzz->{"ldap"}/g   if(defined($href_fuzz->{"ldap"}));
		$str_tmpl[$i] =~ s/FUZZPERL/$href_fuzz->{"perl"}/g   if(defined($href_fuzz->{"perl"}));
		$str_tmpl[$i] =~ s/FUZZHTML/$href_fuzz->{"hmtl"}/g   if(defined($href_fuzz->{"html"}));
		$str_tmpl[$i] =~ s/RND/$r/g;
		#print "XXX str_tmpl modified:\n", Dumper(@str_tmpl);
	}
	return join(' ', @str_tmpl);
}

sub still_one_type_to_fuzz()
{
	return 1 if($flag_fuzz_eol   == 1);
	return 1 if($flag_fuzz_fmt   == 1);
	return 1 if($flag_fuzz_html  == 1);
	return 1 if($flag_fuzz_int32 == 1);
	return 1 if($flag_fuzz_uint32== 1);
	return 1 if($flag_fuzz_ldap  == 1);
	return 1 if($flag_fuzz_perl  == 1);
	return 1 if($flag_fuzz_sep   == 1);
	return 1 if($flag_fuzz_shell == 1);
	return 1 if($flag_fuzz_sql   == 1);
	return 1 if($flag_fuzz_bof   == 1);
	return 0;
}

sub all_types_fuzzed_now()
{
	return 0 if($flag_fuzz_eol   == 1);
	return 0 if($flag_fuzz_fmt   == 1);
	return 0 if($flag_fuzz_html  == 1);
	return 0 if($flag_fuzz_int32 == 1);
	return 0 if($flag_fuzz_uint32== 1);
	return 0 if($flag_fuzz_ldap  == 1);
	return 0 if($flag_fuzz_perl  == 1);
	return 0 if($flag_fuzz_sep   == 1);
	return 0 if($flag_fuzz_shell == 1);
	return 0 if($flag_fuzz_sql   == 1);
	return 0 if($flag_fuzz_bof   == 1);
	return 1;
}

sub fuzz_it($)
{
	my $k = shift;
	my $f = "flag_fuzz_".$k;
	return $$f;
}

sub gen_fuzz_str()
{
	my $href_fuzz = ();
	
	$href_fuzz->{'done'} = 0;
	foreach my $k (@fuzz_types)
	{
# 		print "\nTEST: type '$k'\n";
		
		# are we done?
# 		print "TEST: all types done?\n";
		if(all_types_fuzzed_now())
		{
			$href_fuzz->{'done'} = 1;
			return $href_fuzz;
		}
		
		# should we fuzz this type?
# 		print "TEST: fuzz it?\n";
		next if(fuzz_it($k) == 0);
		
		# do we have support from Fuzz.pm for this type?
# 		print "TEST: func defined\n";
		next unless(defined($Fuzz::func_tab{$k}));
		
		# do we need to reset this fuzz index b/c we are not done yet
# 		print "TEST: maybe reset\n";
		Fuzz::reset_type($k) if(Fuzz::more_avail($k) == 0 && still_one_type_to_fuzz());
		
		# is more available for this type
# 		print "TEST: more available\n";
		if(Fuzz::more_avail($k) == 0)
		{
			# we are done with this type of subsystem to fuzz
			# lets see if this was the last one or if there is
			# still one other type
			${"flag_fuzz_".$k}++;
			if(all_types_fuzzed_now())
			{
				$href_fuzz->{'done'} = 1;
				return $href_fuzz;
			}
		}

# 		print "TEST: call func for $k\n";
		my $func = $Fuzz::func_tab{$k};
		$href_fuzz->{$k} = $func->();
# 		print "\tfuzz str: '$href_fuzz->{$k}'\n";
	}
	return $href_fuzz;
}


#
# Main
#
foreach(@ARGV)
{
	if(/--help/ or /-h/)
	{
		print "usage: main.pl [-h|--help] [reload] [conf=<filename>]\n";
		exit 0;
	}
	$conf_reload = 1	if(/reload/i);
	$conf_fn_config = $1	if(/conf=(.*)/i);
}

parse_config($conf_fn_config);
parse_patternfile($conf_fn_pattern);


# print config
print "date:         $today\n";
print "config file:  $conf_fn_config\n";
print "lastrun file: $conf_fn_lastrun\n";
print "pattern file: $conf_fn_pattern\n";
print "reload:       $conf_reload\n";
print "fuzz types:   \n";
print "\t$_\n" foreach(@fuzz_types);
print "timeout:      $timeout_delay\n\n";

# INIT
if($conf_reload)
{
	print "reload session...\n";
	my $rv = sess_init();
	print "sess_init: problems with file format...\n"   if($rv == -1);
	print "sess_init: problems with record format...\n" if($rv == -2);
	print "sess_init: unknown value type...\n"          if($rv == -3);
	print "sess_init: successfully reloaded.\n"         if($rv ==  0);
}
# call init fuzzing script
system(@conf_scr_init) if(defined($conf_scr_init[0]) and -f $conf_scr_init[0]);
sess_start();
perf_start();

my $cmdstr_fuzz = gen_fuzz(@cmdstr_array);
# print "XXX cmdstr_fuzz:\n", Dumper($cmdstr_fuzz);
# print "XXX cmdstr_array:\n", Dumper(@cmdstr_array);
while(defined($cmdstr_fuzz))
{
# 	print "XXX cmdstr_fuzz:\n", Dumper($cmdstr_fuzz);
# 	print "XXX cmdstr_array:\n", Dumper(@cmdstr_array);
	# call pre fuzzing script
	system(@conf_scr_pre) if(defined($conf_scr_pre[0]) and -f $conf_scr_pre[0]);
	run_prog($cmdstr_fuzz);
	$cmdstr_fuzz = gen_fuzz(@cmdstr_array);
}

# DONE
perf_end();
sess_end();
# call post fuzzing script
system(@conf_scr_post) if(defined($conf_scr_post[0]) and -f $conf_scr_post[0]);

0;

