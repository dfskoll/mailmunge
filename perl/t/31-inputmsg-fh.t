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

my $ctx = parse_and_copy_msg($msg_dir, 't/data/generic-msg', 'copy-this-email');
ok($ctx->mime_entity, 'Successfully parsed sample message');

# Set some fields
$ctx->recipients(['<bar@example.com>']);

write_commands_file($msg_dir, $ctx);
my $ans = mm_mx_ctrl($d, 'scan', 'NOQUEUE', $msg_dir);

is($ans, 'ok', 'Filter succeeded');

my $inputmsg = `cat $msg_dir/INPUTMSG`;
my $copied = `cat $msg_dir/COPIED_EMAIL`;

is ($copied, $inputmsg, 'Message was copied, indicating success of inputmsg_fh()');
END: {
        stop_multiplexor($d);
}

done_testing;

1;
