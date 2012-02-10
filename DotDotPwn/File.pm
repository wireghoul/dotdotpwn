#!/usr/bin/perl
# 
# File Module
# by nitr0us (nitrousenador@gmail.com)
# http://chatsubo-labs.blogspot.com
#
# This module contains functionality to treat filenames and dirnames.
# The main purpose of this module is to split a traversal string
# into its corresponding dirname and filename.

package DotDotPwn::File;
use Exporter 'import';
@EXPORT = qw(split_dirname_filename);

use DotDotPwn::TraversalEngine; # To get the (back)slashes encodings (@Slashes)

sub split_dirname_filename{
	my $trav = shift;
	my $dirname, $filename;

	foreach (@DotDotPwn::TraversalEngine::Slashes){
		if(($last_slash_index = rindex($trav, $_)) != -1){
			$dirname  = substr($trav, 0, $last_slash_index + length);
			$filename = substr($trav, $last_slash_index + length);
		}
	}

	return ($dirname, $filename);
}
