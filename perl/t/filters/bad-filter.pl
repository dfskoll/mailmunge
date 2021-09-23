#!/usr/bin/env perl
#
# A bad filter
#
use strict;
use warnings;

use lib $ENV{TESTDIR} . '/lib';

package BadFilter;
use base qw(Mailmunge::Filter);

sub filter_relay     { return 0; }
sub filter_helo      { return 0; }
sub filter_sender    { return 0; }
sub filter_recipient { return 0; }
sub log_identifier { return 'mailmunge-test-filter-dont-panic'; }

my $filter = BadFilter->new();
$filter->run();
exit(0);
