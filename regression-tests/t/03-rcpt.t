use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg = `cat t/msgs/discard-msg`;

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['tempfail@example.com'], $msg);

my $outfile = maildrop_msg_path();

cmp_deeply($ans, {
           code => 451,
           dsn => '4.3.0',
           txt => 'I tempfail your recipient',
           stage => 'rcpt'}, 'Got expected tempfail at rcpt stage');


$ans = smtp_send($ip, 'continue', 'continue@example.com', ['reject@example.com'], $msg);
cmp_deeply($ans, {
           code => 554,
           dsn => '5.7.1',
           txt => 'I reject your recipient',
           stage => 'rcpt'}, 'Got expected reject at rcpt stage');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);
cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => 'OK',
           stage => 'quit'}, 'Got expected accept at quit stage');

ok(! -r $outfile, "Did not create $outfile");

done_testing;
