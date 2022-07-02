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

my $msg_dir = $d . '/mm-dkim';
mkdir($msg_dir, 0755);

my $ctx = parse_and_copy_msg($msg_dir, 't/data/for-dkim/for-dkim.msg', 'dkim_sign');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/for-dkim/RESULTS`, 'Got expected RESULTS file');

system('rm', '-rf', $msg_dir);
mkdir($msg_dir, 0755);

# Now sign a modified message
$ctx = parse_and_copy_msg($msg_dir, 't/data/for-dkim/for-dkim.msg', 'dkim_sign boilerplate_one_start');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
$ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/for-dkim/RESULTS-MODIFIED`, 'Got expected RESULTS file');

system('rm', '-rf', $msg_dir);

 END: {
        stop_multiplexor($d);
}

done_testing;

1;
