use URI::Escape;

package MyUtils;

#
# output functions
#
sub output_header()
{
	if($conf_output_html)
	{
		printf("<html>\n<head><title>RoR Code Scan of \"%s\"</title></head><body>\n", $conf_dir);
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
		printf "\t\t<td width='30%%'><b>rules dir:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_rulesdir;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>ignore info rules:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_noinfo ? "yes" : "no";
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>ignore low rules:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_nolow ? "yes" : "no";
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>ignore medium rules:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_nomedium ? "yes" : "no";
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>ignore high rules:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_nohigh ? "yes" : "no";
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of rules files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#ruleslist+1;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of rules loaded:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $rules_total;
                printf "\t</tr>\n";

		printf "</table>\n";

		printf "<p>\n";

		printf "<table width='70%%' border='1'>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>search dir:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_dir;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>reduce path:</b></td>\n";
		printf "\t\t<td>%s</td>\n", $conf_reducepath ? "yes" : "no";;
                printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of code files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#filelist+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of views files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#filelist_views+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of modell files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#filelist_models+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of controller files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#filelist_controllers+1;
		printf "\t</tr>\n";

		printf "\t<tr>\n";
		printf "\t\t<td width='30%%'><b>nr. of config files:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $#filelist_config+1;
		printf "\t</tr>\n";

		printf "</table><p>\n";
	}
	else
	{
		printf "rules dir:           %s\n",   $conf_rulesdir;
		printf "ignore info:         %s\n",   $conf_noinfo   ? "yes" : "no";
		printf "ignore low:          %s\n",   $conf_nolow    ? "yes" : "no";
		printf "ignore medium:       %s\n",   $conf_nomedium ? "yes" : "no";
		printf "ignore high:         %s\n",   $conf_nohigh   ? "yes" : "no";
		printf "no rule files:       %i\n",   $#ruleslist+1;
		printf "rules loaded:        %i\n\n", $rules_total;
		printf "search dir:          %s\n",   $conf_dir;
		printf "reduce path:         %s\n",   $conf_reducepath ? "yes" : "no";
		printf "no code files:       %i\n",   $#filelist+1;
		printf "no view files:       %i\n",   $#filelist_views+1;
		printf "no models files:     %i\n",   $#filelist_models+1;
		printf "no controller files: %i\n",   $#filelist_controllers+1;
		printf "no config files:     %i\n\n", $#filelist_config+1;
	}
}

sub output_stat() # fix for noXXX switch
{
	if($conf_output_html)
	{
		printf "<h1>Statistics</h1>";

		printf "<table width='70%%' border='1'>\n";

                printf "\t<tr>\n";
		printf "\t\t<td><b>Hits:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $stat_hits_total;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td><b>Lines analyzed:</b></td>\n";
		printf "\t\t<td>%i</td>\n", $stat_lines_total;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td><b>Physical Source Lines of Code (SLOC):</b></td>\n";
		printf "\t\t<td>%i</td>\n", $stat_sloc;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td><b>Hits\@level:</b></td>\n";
		printf "\t\t<td>[<font color='#0000FF'>info</font>] %i [<font color='#00AA000'>low</font>] %i [<font color='#FFAA00'>medium</font>] %i [<font color='#FF0000'>high</font>] %i</td>\n",
			$stat_hits_info, $stat_hits_low, $stat_hits_medium, $stat_hits_high;
                printf "\t</tr>\n";

                printf "\t<tr>\n";
		printf "\t\t<td><b>Hits\@level+:</b></td>\n";
		printf "\t\t<td>[<font color='#0000FF'>info+</font>] %i [<font color='#00AA000'>low+</font>] %i [<font color='#FFAA00'>medium+</font>] %i [<font color='#FF0000'>high+</font>] %i</td>\n",
			($stat_hits_total)/$stat_kloc,
			($stat_hits_low+$stat_hits_medium+$stat_hits_high)/$stat_kloc,
			($stat_hits_medium+$stat_hits_high)/$stat_kloc,
			($stat_hits_high)/$stat_kloc;
                printf "\t</tr>\n";

		printf "</table>\n";
	}
	else
	{
		printf "\nHits = %i\n",
			$stat_hits_total;
		printf "Lines analyzed = %i\n",
			$stat_lines_total;
		printf "Physical Source Lines of Code (SLOC) = %i\n",
			$stat_sloc;
		printf "Hits\@level = [info] %i [low] %i [medium] %i [high] %i\n",
			$stat_hits_info, $stat_hits_low, $stat_hits_medium, $stat_hits_high;
		printf "Hits/KSLOC\@level+ = [info+] %f [low+] %f [medium+] %f [high+] %f\n\n",
			($stat_hits_total)/$stat_kloc,
			($stat_hits_low+$stat_hits_medium+$stat_hits_high)/$stat_kloc,
			($stat_hits_medium+$stat_hits_high)/$stat_kloc,
			($stat_hits_high)/$stat_kloc;
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
		$color = "#00AA000" if($impact =~ /low/i);
		$color = "#FFAA00" if($impact =~ /medium/i);
		$color = "#FF0000" if($impact =~ /high/i);

		printf "<li>%s:%i [<font color='%s'>%s:%s:rule %i:%s:%s</font>]<br>%s<br><br>",
			$fn, $ln, $color,
			$rule_file, $href_rules->{$rule_file}->{"desc"},
			$rc,
			$impact,
			$href_rules->{$rule_file}->{$rc}->{"cwe"},
			URI::Escape::uri_escape_utf8($l);
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

1;