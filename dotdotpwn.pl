#!/usr/bin/perl
# DotDotPwn - The Directory Traversal Fuzzer
# Copyright (C) 2012 Christian Navarrete and Alejandro Hernandez H.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# ====================================================================
#
#-=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[
#                                                                  -=[
#  DotDotPwn - The Directory Traversal Fuzzer                      -=[
#  is a production of:                                             -=[
#                                                                  -=[
#  CubilFelino                                          Chatsubo   -=[
#  Security Research Lab      and       [(in)Security Dark] Labs   -=[
#  chr1x.sectester.net                chatsubo-labs.blogspot.com   -=[
#  http://twitter.com/chr1x         http://twitter.com/nitr0usmx   -=[
#                                                                  -=[
#-=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[]=--=[
#
#
# Changes (Read CHANGELOG.txt for Details):
#
# * DotDotPwn v3.0.2: The Directory Traversal Fuzzer
#   by nitr0us & chr1x & Contributors (AUTHORS.txt)
#
# * DotDotPwn v2.1: The Directory Traversal Fuzzer
#   by chr1x & nitr0us
#
# * DotDotPwn v2.0: From checker to Fuzzer
#   by nitr0us (nitrousenador@gmail.com)
#   http://chatsubo-labs.blogspot.com
#
# * DotDotPwn v1.0 - Teh Directory Traversal Checker
#   by chr1x@sectester.net
#   http://chr1x.sectester.net
#

use lib qw(.);

$| = 1; # forces a flush after every write or print
$SIG{INT} = \&abort; # When ctrl + C is pressed, the abort function prints useful info

## DotDotPwn Core Modules ##
use DotDotPwn::TraversalEngine;

## DotDotPwn Protocol Modules ##
use DotDotPwn::HTTP;
use DotDotPwn::HTTP_Url;
use DotDotPwn::FTP;
use DotDotPwn::TFTP;
use DotDotPwn::Payload;
use DotDotPwn::STDOUT;

## DotDotPwn Misc Modules ##
use DotDotPwn::Fingerprint;
use DotDotPwn::BisectionAlgorithm;

## Perl modules ##
use Getopt::Std;
#use Switch;

my $DotDotPwn  =
'#################################################################################
#                                                                               #
#  CubilFelino                                                       Chatsubo   #
#  Security Research Lab              and            [(in)Security Dark] Labs   #
#  chr1x.sectester.net                             chatsubo-labs.blogspot.com   #
#                                                                               #
#                               pr0udly present:                                #
#                                                                               #
#  ________            __  ________            __  __________                   #
#  \______ \    ____ _/  |_\______ \    ____ _/  |_\______   \__  _  __ ____    #
#   |    |  \  /  _ \\\\   __\|    |  \  /  _ \\\\   __\|     ___/\ \/ \/ //    \   #
#   |    `   \(  <_> )|  |  |    `   \(  <_> )|  |  |    |     \     /|   |  \  #
#  /_______  / \____/ |__| /_______  / \____/ |__|  |____|      \/\_/ |___|  /  #
#          \/                      \/                                      \/   #
#                              - DotDotPwn v3.0.2 -                             #
#                         The Directory Traversal Fuzzer                        #
#                         http://dotdotpwn.sectester.net                        #
#                            dotdotpwn@sectester.net                            #
#                                                                               #
#                               by chr1x & nitr0us                              #
#################################################################################

';

if(@ARGV < 2){ # -m module required
    print $DotDotPwn; # Banner

    print "Usage: $0 -m <module> -h <host> [OPTIONS]\n";
    print "\tAvailable options:\n";
    print "\t-m\tModule [http | http-url | ftp | tftp | payload | stdout]\n";
    print "\t-h\tHostname\n";
    print "\t-O\tOperating System detection for intelligent fuzzing (nmap)\n";
    print "\t-o\tOperating System type if known (\"windows\", \"unix\" or \"generic\")\n";
    print "\t-s\tService version detection (banner grabber)\n";
    print "\t-d\tDepth of traversals (e.g. deepness 3 equals to ../../../; default: 6)\n";
    print "\t-f\tSpecific filename (e.g. /etc/motd; default: according to OS detected, defaults in TraversalEngine.pm)\n";
    print "\t-E\tAdd \@Extra_files in TraversalEngine.pm (e.g. web.config, httpd.conf, etc.)\n";
    print "\t-S\tUse SSL for HTTP and Payload module (not needed for http-url, use a https:// url instead)\n";
    print "\t-u\tURL with the part to be fuzzed marked as TRAVERSAL (e.g. http://foo:8080/id.php?x=TRAVERSAL&y=31337)\n";
    print "\t-k\tText pattern to match in the response (http-url & payload modules - e.g. \"root:\" if trying /etc/passwd)\n";
    print "\t-p\tFilename with the payload to be sent and the part to be fuzzed marked with the TRAVERSAL keyword\n";
    print "\t-x\tPort to connect (default: HTTP=80; FTP=21; TFTP=69)\n";
    print "\t-t\tTime in milliseconds between each test (default: 300 (.3 second))\n";
    print "\t-X\tUse the Bisection Algorithm to detect the exact deepness once a vulnerability has been found\n";
    print "\t-e\tFile extension appended at the end of each fuzz string (e.g. \".php\", \".jpg\", \".inc\")\n";
    print "\t-U\tUsername (default: 'anonymous')\n";
    print "\t-P\tPassword (default: 'dot\@dot.pwn')\n";
    print "\t-M\tHTTP Method to use when using the 'http' module [GET | POST | HEAD | COPY | MOVE] (default: GET)\n";
    print "\t-r\tReport filename (default: 'HOST_MM-DD-YYYY_HOUR-MIN.txt')\n";
    print "\t-b\tBreak after the first vulnerability is found\n";
    print "\t-q\tQuiet mode (doesn't print each attempt)\n";
    print "\t-C\tContinue if no data was received from host\n";

    exit;
}

getopts("qXOSsCbEm:h:U:P:f:u:k:d:x:t:p:o:r:M:e:");

our $module  = $opt_m || die "Module is neccesary (-m)\n";
our $host    = $opt_h || die "Hostname is neccesary (-h)\n" unless ($module eq "http-url" || $module eq "stdout");
our $user    = $opt_U || 'anonymous';
our $pass    = $opt_P || 'dot@dot.pwn';
our $method  = $opt_M || 'GET';
my  $deep    = $opt_d || 6;
our $bisdeep = 16; # Deepness used when the Bisection Algorithm is going to be used (-X switch)
our $quiet   = $opt_q;
our $break   = $opt_b;
our $url     = $opt_u;
my  $ssl     = $opt_S;
our $pattern = $opt_k;
my  $file    = $opt_f;
our $extra_f = $opt_E;
our $extens  = $opt_e;
my  $OS      = $opt_O;
my  $o_type  = $opt_o;
my  $serv    = $opt_s;
my  $ping    = $opt_C;
our $bisect  = $opt_X;
our $time    = ($opt_t || 300) * 1000; # Time in milliseconds between each test
our $start_time; # Will hold the time at the beginning of execution
our $runtime;    # Will hold the difference between the end time and $start_time, so, it's the runtime
my  $payload_file = $opt_p;
our $payload; # The content of $payload_file
my  $proto_url;
my  $proto;
our $port;
our $dot_quiet_mode = 10; # When quiet mode is enabled, print a dot (.) each 10 attempts
my  $n_travs = 0; # Counter of Traversals found
our @traversals;  # Traversal strings generated by the Traversal Engine that will be launched against the target

print $DotDotPwn if $module ne "stdout";


# Variable asignment and other validations per module
#switch($module){
if ($module eq "ftp")  { 
	$port = $opt_x || 21; 
} elsif ($module eq "http") { 
	$port = $ssl ? 443 : 80; $port = $opt_x if $opt_x; 
} elsif ($module eq "tftp") { 
	$port = $opt_x || 69;
} elsif ($module eq "http-url") {
	die "URL is neccesary (-u)\n" unless $url;

	# URL Parsing
	die "Invalid URL format!\n" if $url !~ m|(\w+)://([\w\.\-]+):?(\d*)?/|;

	$port = 80;
	$proto_url = $1;
	$port = 443 if ($proto_url eq 'https');
	$host  = $2;
	$port = $3 if $3;

	#die "'$proto_url' Protocol not supported\n" if $proto_url ne "http";
	die "No \"TRAVERSAL\" keyword found in the supplied URL\n" if $url !~ /TRAVERSAL/;
	die "Pattern string to match is neccesary (-k)\n" unless $pattern;
} elsif ($module eq "payload") {
	$port = $opt_x || die "Port number is necessary (-x)\n";
	die "Payload file is necessary (-p)\n" unless $payload_file;
	die "Pattern string to match is neccesary (-k)\n" unless $pattern;

	open PAYLOAD_FD, $payload_file or die "Cannot open $payload_file: $!";

	# Undef the end of record character to read the whole file into one scalar variable
	undef $/;

	$payload = <PAYLOAD_FD>;

	close PAYLOAD_FD;

	$/ = "\n"; # Restore for normal behaviour

	die "No \"TRAVERSAL\" keyword found in the supplied payload file\n" if $payload !~ /TRAVERSAL/;
} elsif ($module eq "stdout") {
	@traversals = TraversalEngine(OS_type($o_type), $deep, $file);
	toSTDOUT();
	exit;
} else { print "[-] Invalid Module ($module)!\n"; exit; }
#}


($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);

our $report;

if($opt_r) {
	$report = "Reports/" . $opt_r;
} else {
	$report = sprintf "Reports/%s_%02d-%02d-%d_%02d-%02d.txt", $host, $mon+1, $mday, $year+1900, $hour, $min;
}

print "[+] Report name: $report\n";

open(REPORT , ">$report");

printf REPORT "\n[+] Date and Time: %02d-%02d-%4d %02d:%02d:%02d\n",$mon+1, $mday, $year+1900, $hour, $min, $sec;

# Target information
for my $fh (STDOUT, REPORT) {
	print $fh "\n[========== TARGET INFORMATION ==========]\n";
	print $fh "[+] Hostname: $host\n";
}

if($OS){
	for my $fh (STDOUT, REPORT) { print $fh "[+] Detecting Operating System (nmap) ...\n"; }
	$target_OS = OS_Detection($host);
	for my $fh (STDOUT, REPORT) { print $fh "[+] Operating System detected: " . $target_OS . "\n"; }
}

# Manual definition of OS type if known
if($o_type) {
	if( ($o_type eq "unix") || ($o_type eq "windows") || ($o_type eq "generic") ) {
		$target_OS = $o_type; # Overwrite the previously OS type detected by nmap. It has more importance!
		for my $fh (STDOUT, REPORT) { print $fh "[+] Setting Operating System type to \"" . $target_OS . "\"\n"; }
	} else {
		for my $fh (STDOUT, REPORT) { print "[-] Invalid OS type \"" . $o_type . "\"... Using the previously detected by nmap (if -O enabled)\n"; }
	}
}

$proto = $proto_url || ($module eq "payload" ? "N/A" : $module);

for my $fh (STDOUT, REPORT) { print $fh "[+] Protocol: $proto\n"; }
for my $fh (STDOUT, REPORT) { print $fh "[+] Port: $port\n"; }
for my $fh (STDOUT, REPORT) { print $fh "[+] Service detected:\n" . Banner_Grabber($host, $port, $proto) if $serv; }


#Traversal Engine
for my $fh (STDOUT, REPORT) { print $fh "\n[=========== TRAVERSAL ENGINE ===========]\n"; }
@traversals = TraversalEngine(OS_type($target_OS), $deep, $file);
for my $fh (STDOUT, REPORT) { print $fh "[+] Traversal Engine DONE ! - Total traversal tests created: " . scalar(@traversals) . "\n"; }


# Testing
print  "\n[=========== TESTING RESULTS ============]\n";
printf "[+] Ready to launch %.2f traversals per second\n", (1000000 / $time);
print  "[+] Press Enter to start the testing (You can stop it pressing Ctrl + C)\n";
<STDIN>;

$start_time = time;

# (nitr0us)
# "use Switch" Added here again to avoid an existing bug in Switch.pm @ Perl 5.8 
# that raises an error in the next switch($module) statement
#
# http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=480106
#use Switch;

#switch($module){
if ($module eq "ftp")      { $n_travs = FuzzFTP($host, $port, $user, $pass); }
if ($module eq "http")     { $n_travs = FuzzHTTP($host, $port, $ssl, $method, $ping); }
if ($module eq "tftp")     { $n_travs = FuzzTFTP($host, $port); }
if ($module eq "payload")  { $n_travs = FuzzPayload($host, $port, $ssl, $payload); }
if ($module eq "http-url") { $n_travs = FuzzHTTP_Url($url, $ping); }
#}

$runtime = time - $start_time;
for my $fh (STDOUT, REPORT) {
	printf $fh "\n[+] Fuzz testing finished after %.2f minutes ($runtime seconds)\n", ($runtime / 60);
	print  $fh "[+] Total Traversals found: $n_travs\n";
}

print "[+] Report saved: $report\n";

exit 31337;


# Handler of Ctrl + C
sub abort{
	# Don't know why, but the switch() statement never worked here =/

	if   ($module eq "ftp")      { $n_travs = $DotDotPwn::FTP::n_travs; }
	elsif($module eq "http")     { $n_travs = $DotDotPwn::HTTP::n_travs; }
	elsif($module eq "http-url") { $n_travs = $DotDotPwn::HTTP_Url::n_travs; }
	elsif($module eq "tftp")     { $n_travs = $DotDotPwn::TFTP::n_travs; }
	elsif($module eq "payload")  { $n_travs = $DotDotPwn::Payload::n_travs; }

	for my $fh (STDOUT, REPORT) {
		print $fh "\n[+] Total Traversals found: $n_travs\n";
		print $fh "[-] Fuzz testing aborted\n";
	}

	print "[+] Report saved: $report\n";

	exit;
}
