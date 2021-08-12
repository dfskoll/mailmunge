use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Test::Mailmunge::Tmpdir;
use Test::Mailmunge::Utils;

my $t = Test::Mailmunge::Tmpdir->new();
my $d = $t->{dir};

start_multiplexor($d, 't/filters/bad-filter.pl');

my $ans = mm_mx_ctrl($d, 'relayok', '10.0.0.1', 'foo.example.com', '4567', '127.0.0.1', '25', 'qid-goes-here');
is($ans, 'ok -1 Internal software error 451 4.3.0 0', 'Got expected result from relayok 10.0.0.1');

END: {
        stop_multiplexor($d);
}

done_testing;
