#!/usr/bin/perl

# Copyright (C) 2015-2021 Theo Niessink <theo@taletn.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

use strict;
use warnings;

use File::Find;

if($#ARGV != 0 or $ARGV[0] !~ /^--(dry-run|force)$/) {
  $_ = $0; $_ = $& if(/[^\/\\]+$/);
  print <<EOF;
Usage: $_ --dry-run | --force

Removes all files from libtommath/ and libtomcrypt/, except those C source
files (*.c, *.h) that are actually used in makefile.msvc.
EOF
  exit 1;
}
my $dry_run = $1 ne 'force';

my %required = ();
open(FILE, '<makefile.msvc') or die "$!\n";
binmode(FILE);
while(<FILE>) {
  tr/\r\n//d;
  next unless(/^\s*(libtom(?:math|crypt)\S+\.(?:obj|h|c))/);
  $_ = $1;
  tr/\\/\//;
  s/\.obj$/.c/;
  $required{$_} = 1;
}
close(FILE);
my @required = keys %required;
undef %required;

push(@required, qw(libtommath/changes.txt libtommath/LICENSE));
push(@required, qw(libtomcrypt/changes libtomcrypt/LICENSE));

my @files = ();
my @dirs = ();

sub wanted {
  if(-f) {
    push @files, $File::Find::name;
  } elsif(-d) {
    push @dirs, $File::Find::name;
  }
}

find(\&wanted, qw(libtommath libtomcrypt));

foreach my $file (@files) {
  $file =~ tr/\\/\//;
  if (!grep(/^\Q$file\E$/, @required)) {
    print "$file\n" if($dry_run or unlink($file));
    warn "[FAILED] $file\n" if(!$dry_run and -f $file);
  }
}

foreach my $dir (sort { length($b) <=> length($a) } @dirs) {
  rmdir($dir) unless($dry_run);
}
