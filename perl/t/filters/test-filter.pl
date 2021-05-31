#!/usr/bin/env perl
#
# The default filter that just accepts everything and
# does nothing.
#
use strict;
use warnings;

use lib $ENV{TESTDIR} . '/lib';

use Test::Mailmunge::Filter;

my $filter = Test::Mailmunge::Filter->new();
$filter->run();
exit(0);
