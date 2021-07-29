use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Test::Mailmunge::Tmpdir;
use Test::Mailmunge::Utils;
use JSON::Any;
use IO::Socket::INET;

my $t = Test::Mailmunge::Tmpdir->new();
my $d = $t->{dir};

my $port = $ENV{RSPAMD_PORT} || 11333;
my $sock = IO::Socket::INET->new(PeerHost => '127.0.0.1',
                                 PeerPort => $port,
                                 Proto    => 'tcp',
                                 Timeout  => 3);
if (!$sock) {
        plan skip_all => "Cannot connect to rspamd on port $port; skipping rspamd tests";
}

start_multiplexor($d, 't/filters/test-filter.pl');

my $msg_dir = $d . '/mm-foobar';
mkdir($msg_dir, 0755);

my $ctx = parse_and_copy_msg($msg_dir, 't/data/generic-msg', 'rspamd');

ok($ctx->mime_entity, 'Successfully parsed sample message');
$ctx->recipients(['<bar@example.com>', '<wug@example.com>']);
write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'qIa12345', $msg_dir);
is($ans, 'ok', 'Filter succeeded');
ok(-f "$msg_dir/RSPAMD_RESULTS", "We have rspamd results");
my $ret;
eval {
        my $stuff = `cat "$msg_dir/RSPAMD_RESULTS"`;
        $ret = JSON::Any->jsonToObj($stuff);
};

ok($ret->{response}, "We have a 'response' element");
ok($ret->{response}->{status}, "And the response elemenet has a 'status' element");
ok($ret->{results}, "We have a 'results' element");
ok($ret->{results}->{symbols}->{RCPT_COUNT_ONE}. 'RCPT_COUNT_ONE test fired');
ok($ret->{results}->{symbols}->{TO_EQ_FROM} . 'TO_EQ_FROM test fired');
ok($ret->{results}->{symbols}->{PRECEDENCE_BULK} . 'PRECEDENCE_BULK test fired');

END: {
        stop_multiplexor($d);
}

done_testing;

1;
