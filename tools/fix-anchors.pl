#!/usr/bin/env perl
use strict;
use warnings;

# Build the old-to-new anchor dictionary

my $anchor_dictionary = {};

foreach my $file (@ARGV) {
        slurp($file);
}

# Now fix them
foreach my $file (@ARGV) {
        fix($file);
}

exit(0);

sub slurp
{
        my ($file) = @_;
        my $fh;
        return unless open($fh, '<', $file);

        while (<$fh>) {
                chomp;

                if (/id="(.*)">(.*)</) {
                        my $new = $1;
                        my $text = $2;
                        $text =~ s/^\s+//;
                        $text =~ s/\s+$//;
                        if ($new ne $text) {
                                if ($text =~ /([^\(]+)\(/) {
                                        my $old = $1;
                                        $old =~ s/^\s+//;
                                        $old =~ s/\s+$//;
                                        $anchor_dictionary->{$file}->{$old} = $new;
                                }
                        }
                }
        }
}

sub fix_href
{
        my ($href) = @_;

        unless ($href =~/^(.+)\#(.+)$/) {
                return "href=\"$href\"";
        }

        my $file = $1;
        my $anchor = $2;

        return "href=\"$href\"" unless exists $anchor_dictionary->{$file};
        return "href=\"$href\"" unless exists $anchor_dictionary->{$file}->{$anchor};

        my $new = $anchor_dictionary->{$file}->{$anchor};
        return "href=\"$file\#$new\"";
}

sub fix
{
        my ($file) = @_;

        my($ifh, $ofh);
        return unless open($ifh, '<', $file);
        if (!open($ofh, '>', "$file.fixed")) {
                $ifh->close();
                return;
        }
        while(<$ifh>) {
                s/href="([^\"]+)"/fix_href($1)/ge;
                print $ofh $_;
                # Put a back-link back to index... cheeeeesy
                if ($_ eq "<body>\n" && $file ne 'pod_index.html') {
                        print $ofh "<p><a href=\"index.html\">&#8592; Documentation Index</a></p>\n";
                }
        }
        $ifh->close();
        $ofh->close();
        rename("$file.fixed", "$file");
}

1;
