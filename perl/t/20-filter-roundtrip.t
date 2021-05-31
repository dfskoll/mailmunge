use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Test::Mailmunge::Tmpdir;
use Test::Mailmunge::Utils;

my $t = Test::Mailmunge::Tmpdir->new();
my $d = $t->{dir};

start_multiplexor($d, 't/filters/test-filter.pl');

my $ans = mm_mx_ctrl($d, 'relayok', '10.0.0.1', 'foo.example.com', '4567', '127.0.0.1', '25', 'qid-goes-here');
is($ans, 'ok 1 ok 250 2.1.0 0', 'Got expected result from relayok 10.0.0.1');

$ans = mm_mx_ctrl($d, 'relayok', '10.0.0.2', 'foo.example.com', '4567', '127.0.0.1', '25', 'qid-goes-here');
is($ans, 'ok -1 Whoops 451 4.3.0 0', 'Got expected result from relayok 10.0.0.2');

$ans = mm_mx_ctrl($d, 'relayok', '10.0.0.3', 'foo.example.com', '4567', '127.0.0.1', '25', 'qid-goes-here');
is($ans, 'ok 0 GO AWAY 554 5.7.1 0', 'Got expected result from relayok 10.0.0.3');

$ans = mm_mx_ctrl($d, 'relayok', '10.0.0.4', 'foo.example.com', '4567', '127.0.0.1', '25', 'qid-goes-here');
is($ans, 'ok 2 I love you 250 2.1.0 0', 'Got expected result from relayok 10.0.0.4');

$ans = mm_mx_ctrl($d, 'scan', 'NOQUEUE', "$d/mm-foo");
like($ans, qr/error: Could not chdir/, 'Got expected error message for nonexistent directory');

END: {
        stop_multiplexor($d);
}

done_testing;
