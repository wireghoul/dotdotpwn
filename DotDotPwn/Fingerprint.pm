#!/usr/bin/perl
# 
# Fingerprint Module
# by nitr0us (nitrousenador@gmail.com)
# http://twitter.com/nitr0usmx
# http://chatsubo-labs.blogspot.com
#
# This module performs the Operating System detection (-O switch),
# service detection (-s switch) and OS type detection based in the
# "OS detail" string provided by nmap.
#

package DotDotPwn::Fingerprint;
use Exporter 'import';
@EXPORT = qw(OS_Detection Banner_Grabber OS_type);

use Socket qw/ :DEFAULT :crlf /; # $CRLF
use IO::Socket;
#use Switch;

$| = 1;

# Detect the target OS with the help of nmap (http://www.nmap.org)
sub OS_Detection{
	my $host = shift;

	if($> !=0){
		print "[-] You need r00t privileges in order to use the OS detection feature (-O)\n";
		exit;
	}

	my $nmap = "nmap -O -PN -T4 $host 2> /dev/null | grep 'OS details' | cut -d ':' -f 2 | tr -d '\\n'";

	return `$nmap`;
}

# A simple TCP banner grabber
sub Banner_Grabber{
	my ($host, $port, $proto) = @_;
	my $response;
	my $banner;

	return "N/A" if $proto eq "tftp";

	$sock = IO::Socket::INET->new(	PeerAddr => $host,
					PeerPort => $port,
					Proto => 'tcp')
		or die "[-] Couldn't connect to $host on port $port: $!\n";

	#switch($proto){
	if ($proto eq "http") {
		$sock->send("HEAD / HTTP/1.0" . $CRLF . $CRLF);
		$sock->recv($response, 1024);

		if($response =~ /Server: (.*)/){
			$sock->close();
			$banner = $1;
		} else {
			$sock2 = IO::Socket::INET->new(	PeerAddr => $host,
							PeerPort => $port,
							Proto => 'tcp')
				or die "[-] Couldn't connect to $host on port $port: $!\n";

			$sock2->send("HEAD / HTTP/1.1" . $CRLF . $CRLF);
			$sock2->recv($response, 1024);

			if($response =~ /Server: (.*)/){
				$sock2->close();
				$banner = $1;
			}

			$sock2->close();
		}
	} else {
		$sock->recv($response, 1024);
		$banner = $response;
	}
	#}

	$sock->close();

	return $banner;
}

sub OS_type{
	my $OS_string = shift;
        
        my @unixes=('linux','bsd','solaris','aix','irix','mac','unix');
        my @windoz=('windows','micosoft');
	if (grep /$OS_string/i, @unixes ) { 
		return "unix"; 
 	} elsif (grep /$OS_string/i, @windoz) {
		return "windows";
	} else {
		return "generic";
	}
}
