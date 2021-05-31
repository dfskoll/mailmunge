#!/usr/bin/env perl
use strict;
use warnings;

use HTML::Parser;

sub echo
{
        my ($text) = @_;
        print $text;
}

sub start
{
        my ($tagname, $attr, $text) = @_;
        if (lc($tagname) eq 'a') {
                if ($text !~ /https?:/) {
                        if ($text =~ /^(.*href=")(.*)(".*)$/i) {
                                my $pre = $1;
                                my $href = $2;
                                my $post = $3;
                                $href =~ s|/|__|g;
                                $text = $pre . $href . $post;
                        }
                }
        }
        print $text;
}

my $p =  HTML::Parser->new(api_version => 3,
                           start_h => [\&start, "tagname,attr,text"],
                           default_h => [\&echo, "text"]);

$p->parse_file(*STDIN);
