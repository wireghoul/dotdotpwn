#!/usr/bin/perl
# 
# HTTP Parameters module
# by nitr0us (nitrousenador@gmail.com)
# http://chatsubo-labs.blogspot.com
#
# In this module resides the functionality to substitute
# the 'TRAVERSAL' tokens in the supplied URL by the fuzz
# patterns created by the Traversal Engine.
# Once subsituted, the request is sent to the target and the 
# module waits for the response.
# Thereafter, it checks if the string pattern passed as a 
# parameter (-k switch) exists in the server's response, 
# if so, it's considered vulnerable.
# 

package DotDotPwn::HTTP_Url;
use Exporter 'import';
@EXPORT = qw(FuzzHTTP_Url);

use DotDotPwn::BisectionAlgorithm;

use HTTP::Lite;
use Time::HiRes qw(usleep);

sub FuzzHTTP_Url{
	my ($url, $bisection_request) = @_;
	our $n_travs = 0;
	my $foo = 0; # Used as an auxiliary variable in quiet mode (see below)
	my $UserAgent;

	open(AGENTS, "DotDotPwn/User-Agents.txt") or die "[-] Cannot open User-Agents.txt file: $!";
	my @UserAgents = <AGENTS>;
	close(AGENTS);

	for(@UserAgents) { chomp; }

	if(!$bisection_request){
		open(REPORT , ">>$main::report");

		for my $fh (STDOUT, REPORT) { print $fh "[+] Replacing \"TRAVERSAL\" with the traversals created and sending\n"; }
	}

	foreach $traversal (@main::traversals){
		my $http = new HTTP::Lite;

		$UserAgent = @UserAgents[int(rand(@UserAgents))];
		$http->add_req_header("User-Agent", $UserAgent);

		$tmp_url = $url; # Not to overwrite the TRAVERSAL token
		$tmp_url =~ s/TRAVERSAL/$traversal/g;

		# Return 1 (vulnerable) or 0 (not vulnerable) to BisectionAlgorithm()
		if($bisection_request){
			$http->request($bisection_request);

			if($http->body() =~ /$main::pattern/s ){
				return 1; # Vulnerable
			} else {
				return 0; # Not Vulnerable
			}
		}

		if(!$http->request($tmp_url)){
			my $runtime = time - $main::start_time;
			for my $fh (STDOUT, REPORT) {
				printf $fh "\n[+] Fuzz testing finished after %.2f minutes ($runtime seconds)\n", ($runtime / 60);
				print  $fh "[+] Total Traversals found (so far): $n_travs\n";
			}

			die "[-] Web server didn't respond !\n";
		}

		if($http->body() =~ /$main::pattern/s ){
			for my $fh (STDOUT, REPORT) { print $fh "\n[*] Testing URL: $tmp_url <- VULNERABLE\n"; }
			$n_travs++;

			if($main::bisect){
				print "\n[========= BISECTION ALGORITHM  =========]\n\n";
				DotDotPwn::BisectionAlgorithm::BisectionAlgorithm(1, $main::bisdeep, $tmp_url);

				return 1;
			}

			return $n_travs if $main::break;

			usleep($main::time);
			next;
		}

		if($main::quiet){
			print ". " unless $foo++ % $main::dot_quiet_mode;
		} else {
			print "[*] Testing URL: $tmp_url\n";
		}

		usleep($main::time);
	}

	return $n_travs;
}
