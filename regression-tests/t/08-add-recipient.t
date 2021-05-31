use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg;
my $dir = maildrop_msg_dir();

clean_maildrop_dir();
clean_mta_queues();

$msg = make_msg('addrcpt', 'generic-msg', 'out-%DEST%');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files("$dir/out-user1", "$dir/out-user5");

ok(-r "$dir/out-user1", 'Mail was delivered to original recipient');
ok(-r "$dir/out-user5", '... and also to the added recipient');

done_testing;
