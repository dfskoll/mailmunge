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

my $ctx = parse_and_copy_msg($msg_dir, 't/data/msg-with-exe/inputmsg');
ok($ctx->mime_entity, 'Successfully parsed sample message');

# Set some fields
$ctx->recipients(['<bar@example.com>']);

write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'NOQUEUE', $msg_dir);

is($ans, 'ok', 'Filter succeeded');
is(`cat t/data/msg-with-exe/RESULTS`, `cat $msg_dir/RESULTS`, 'Got expected RESULTS file');
is(`cat t/data/msg-with-exe/NEWBODY`, `cat $msg_dir/NEWBODY`, 'Got expected NEWBODY file');



END: {
        stop_multiplexor($d);
}

done_testing;

1;
