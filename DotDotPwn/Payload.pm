#!/usr/bin/perl
# 
# Payload Module
# by nitr0us (nitrousenador@gmail.com)
# http://chatsubo-labs.blogspot.com
#
# This module takes the text file passed as a parameter (-p filename),
# replaces the 'TRAVERSAL' token within the file by the traversal
# fuzz patterns and sends the payload (file content + fuzz patterns)
# to the target (-h switch) in the specified port (-x switch).
# (e.g. a file that contains an HTTP request including cookies, 
# session ids, variables, etc. and the 'TRAVERSAL' tokens within the
# request that will be fuzzed)
#

package DotDotPwn::Payload;
use Exporter 'import';
@EXPORT = qw(FuzzPayload);

use DotDotPwn::BisectionAlgorithm;

use IO::Socket;
use IO::Socket::SSL;
use Time::HiRes qw(usleep);

sub FuzzPayload{
	my ($host, $port, $ssl, $payload, $bisection_request) = @_;
	my $sock, $response;
	our $n_travs = 0;
	my $foo = 0; # Used as an auxiliary variable in quiet mode (see below)

	if(!$bisection_request){
		open(REPORT , ">>$main::report");
	}

	foreach $traversal (@main::traversals){
		$tmp_payload = $payload;
		$tmp_payload =~ s/TRAVERSAL/$traversal/g;

    if ($ssl) {
      $sock = IO::Socket::SSL->new(
        PeerAddr => $host,
        PeerPort => $port,
      );
    } else {
      $sock = IO::Socket::INET->new(
        PeerAddr => $host,
				PeerPort => $port,
      );
    }
    if (!$sock) {
			my $runtime = time - $main::start_time;
			for my $fh (STDOUT, REPORT) {
				printf $fh "\n[+] Fuzz testing finished after %.2f minutes ($runtime seconds)\n", ($runtime / 60);
				print  $fh "[+] Total Traversals found (so far): $n_travs\n";
			}
			die "[-] Host $host didn't respond on port $port!\n";			
		}

		# Return 1 (vulnerable) or 0 (not vulnerable) to BisectionAlgorithm()
		if($bisection_request){
			print $sock $bisection_request;

			$sock->read($response, 8192);

			if( $response =~ /$main::pattern/s ){
				$sock->close();
				return 1; # Vulnerable
			} else {
				$sock->close();
				return 0; # Not Vulnerable
			}
		}

		print $sock $tmp_payload;

		$sock->read($response, 8192);

		if( $response =~ /$main::pattern/s ){
			for my $fh (STDOUT, REPORT) { print $fh "\n[*] VULNERABLE PAYLOAD:\n$tmp_payload\n"; }
			$n_travs++;

			if($main::bisect){
				print "\n[========= BISECTION ALGORITHM  =========]\n\n";

 				DotDotPwn::BisectionAlgorithm::BisectionAlgorithm(1, $main::bisdeep, $tmp_payload);

				return 1;
			}

			return $n_travs if $main::break;

			usleep($main::time);
			next;
		}

		$sock->close();

		if($main::quiet){
			print ". " unless $foo++ % $main::dot_quiet_mode;
		} else{
			print "[*] Payload with: $traversal\n";
		}

		usleep($main::time);
	}

	return $n_travs;
}
