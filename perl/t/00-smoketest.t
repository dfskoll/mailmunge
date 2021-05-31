use strict;
use warnings;

use lib './lib';

use Test::More;
use File::Find::Rule;

my @files = File::Find::Rule->file()->name('*.pm')->in('lib', 't/lib');

my @bad_files;
foreach my $filename (@files) {
        my $pkg = $filename;
        $pkg =~ s{^lib/(.*)\.pm$}{$1}g;
        $pkg =~ s{^t/lib/(.*)\.pm$}{$1}g;
        $pkg =~ s{/}{::}g;
        eval "require $pkg";
        ok( ! $@, "File $filename has no syntax errors" );
        if( $@ ) {
                diag( $@ );
                push @bad_files, $filename;
        }
}
if( scalar @bad_files ) {
        diag('');
        diag("File $_ failed compilation") for @bad_files;
        BAIL_OUT(scalar @bad_files .  ' perl files did not compile');
}

done_testing;
