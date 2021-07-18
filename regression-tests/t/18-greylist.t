use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg = make_msg('nothing-fancy', 'generic-msg', 'greylistfile');

$ans = smtp_send($ip, 'continue', 'greylist@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
        code => 451,
        dsn => '4.3.0',
        stage => 'rcpt',
        txt => 'Greylisting in effect; please try again in 0 second(s)'},
           'Got expected tempfail at RCPT stage');

$ans = smtp_send($ip, 'continue', 'greylist@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
        code => 200,
        dsn => '2.0.0',
        txt => 'OK',
        stage => 'quit'}, 'Got expected accept at quit stage');

done_testing;
