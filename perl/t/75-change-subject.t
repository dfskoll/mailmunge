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

my $msg_dir = $d . '/mm-foobar';
mkdir($msg_dir, 0755);

my $ctx = parse_and_copy_msg($msg_dir, 't/data/generic-msg', 'chgsub');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>', '<wug@example.com>']);
write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');
ok(results_has_lines($msg_dir, 'ISubject 1 [New%20subject]%20chgsub', 'F'),
   'Got expected lines in RESULTS');

END: {
        stop_multiplexor($d);
}

done_testing;

1;
