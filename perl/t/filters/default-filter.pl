#!/usr/bin/env perl
#
# The default filter that just accepts everything and
# does nothing.
#
use strict;
use warnings;

use lib 'lib';

use Mailmunge::Filter;

my $filter = Mailmunge::Filter->new();
$filter->run();
exit(0);
