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

#### Boilerplate at start of first part
my $ctx = parse_and_copy_msg($msg_dir, 't/data/for-boilerplate.msg', 'boilerplate_one_start');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/boilerplate/RESULTS`, 'Got expected RESULTS file');
is(`cat $msg_dir/NEWBODY`, `cat t/data/boilerplate/one_atstart/NEWBODY`, 'Got expected NEWBODY file');

system('rm', '-rf', $msg_dir);
mkdir($msg_dir, 0755);

#### Boilerplate at end of first part
$ctx = parse_and_copy_msg($msg_dir, 't/data/for-boilerplate.msg', 'boilerplate_one_end');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
$ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/boilerplate/RESULTS`, 'Got expected RESULTS file');
is(`cat $msg_dir/NEWBODY`, `cat t/data/boilerplate/one_atend/NEWBODY`, 'Got expected NEWBODY file');

system('rm', '-rf', $msg_dir);
mkdir($msg_dir, 0755);

#### Boilerplate at start of all parts
$ctx = parse_and_copy_msg($msg_dir, 't/data/for-boilerplate.msg', 'boilerplate_all_start');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
$ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/boilerplate/RESULTS`, 'Got expected RESULTS file');
is(`cat $msg_dir/NEWBODY`, `cat t/data/boilerplate/all_atstart/NEWBODY`, 'Got expected NEWBODY file');

system('rm', '-rf', $msg_dir);
mkdir($msg_dir, 0755);

#### Boilerplate at end of all parts
$ctx = parse_and_copy_msg($msg_dir, 't/data/for-boilerplate.msg', 'boilerplate_all_end');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>']);
write_commands_file($msg_dir, $ctx);
$ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');

is(`cat $msg_dir/RESULTS`, `cat t/data/boilerplate/RESULTS`, 'Got expected RESULTS file');
is(`cat $msg_dir/NEWBODY`, `cat t/data/boilerplate/all_atend/NEWBODY`, 'Got expected NEWBODY file');

END: {
        stop_multiplexor($d);
}

done_testing;

1;
