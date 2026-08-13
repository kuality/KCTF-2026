#!/usr/bin/env perl
use strict;
use warnings;
use bytes;

my $path = shift @ARGV // die "usage: scrub_release.pl BINARY\n";
die "unexpected extra arguments\n" if @ARGV;

open my $input, '<:raw', $path or die "open $path: $!\n";
local $/;
my $data = <$input>;
close $input or die "close $path: $!\n";

my @replacements = (
  ['.extract_payload', '.fn_000000000000'],
  ['.round_function', '.fn_00000000000'],
  ['.valid_capsule', '.fn_0000000000'],
  ['.constant_time_equal', '.fn_0000000000000000'],
  ['.byte_set', '.fn_00000'],
  ['.byte_get', '.fn_00000'],
  ['.capsule', '.value00'],
  ['.verify', '.fn0000'],
  ['.apply', '.f0000'],
  ['.run', '.f00'],
  ['program_data.ml', 'unit00000000.ml'],
  ['engine.ml', 'unit01.ml'],
  ['main.ml', 'unit.ml'],
  ['Program_data', 'UnitBBBBBBBB'],
  ['Tape_types', 'UnitCCCCCC'],
  ['Engine', 'UnitAA'],
  ['Main', 'Unit'],
);

my $changed = 0;
for my $pair (@replacements) {
  my ($from, $to) = @$pair;
  die "replacement length mismatch for $from\n" if length($from) != length($to);
  my $count = ($data =~ s/\Q$from\E/$to/g);
  $changed += $count;
}
die "no release metadata was scrubbed\n" if $changed == 0;

open my $output, '>:raw', $path or die "open $path: $!\n";
print {$output} $data or die "write $path: $!\n";
close $output or die "close $path: $!\n";
