#!/usr/bin/perl -w
use strict;
use warnings;

# Check if a filename is provided
if (@ARGV != 1) {
    die "Usage: $0 filename\n";
}

my $filename = $ARGV[0];

# Open the file for reading
open(my $fh, '<', $filename) or die "Could not open file '$filename' $!";

# Read the file line by line and remove newline characters
my @lines;
while (my $line = <$fh>) {
    chomp $line;
    push @lines, $line;
}

# Close the file
close($fh);

# Join the lines with a comma and print the result
my $result = join(',', @lines);
print "$result\n";
