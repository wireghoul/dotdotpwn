### DESCRIPTION ###

DotDotPwn - The Directory Traversal Fuzzer

It's a very flexible intelligent fuzzer to discover traversal 
directory vulnerabilities in software such as HTTP/FTP/TFTP 
servers, Web platforms such as CMSs, ERPs, Blogs, etc. 

Also, it has a protocol-independent module to send the desired 
payload to the host and port specified. On the other hand, it 
also could be used in a scripting way using the STDOUT module.

It's written in perl programming language and can be run 
either under OS X, *NIX or Windows platforms. It's the first Mexican 
tool included in BackTrack Linux (BT4 R2).

Fuzzing modules supported in this version: 
- HTTP
- HTTP URL
- FTP
- TFTP
- Payload (Protocol independent)
- STDOUT


### REQUIREMENTS ###

- Perl (http://www.perl.org)
Programmed and tested on Perl 5.8.8 and 5.10

- Nmap (http://www.nmap.org)
Only if you plan to use the OS detection feature
(needs root privileges)

Perl modules:
- Net::FTP
- TFTP (only required if fuzzing TFTP)
- Time::HiRes
- Socket
- IO::Socket
- Getopt::Std

You can easily install the missing modules doing the 
following as root:

```
# perl -MCPAN -e "install <MODULE_NAME>"
```

or

```
# cpan 
cpan> install <MODULE_NAME>
```


### EXAMPLES ###

Read EXAMPLES.txt


### CONTACT ###

Official Website: http://dotdotpwn.sectester.net
Official Email:   dotdotpwn@sectester.net
Bugs / Contributions / Improvements: dotdotpwn@sectester.net


### AUTHORS ###

```
 Christian Navarrete aka chr1x         Alejandro Hernandez H. aka nitr0us
   http://twitter.com/chr1x              http://twitter.com/nitr0usmx
      chr1x@sectester.net                  nitrousenador@gmail.com
                                         http://www.brainoverflow.org

 CubilFelino Security Research Lab     Chatsubo [(in)Security Dark] Labs
   http://chr1x.sectester.net          http://chatsubo-labs.blogspot.com   
```

### CHANGE HISTORY ###

Read CHANGELOG.txt

### LICENSE ###

```
DotDotPwn - The Directory Traversal Fuzzer
Copyright (C) 2012 Christian Navarrete and Alejandro Hernandez H.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
```
