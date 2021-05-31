use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg;
my $outfile = maildrop_msg_path();

clean_quarantine_dir();
clean_mta_queues();

$msg = make_msg('boilerplate_one_start', 'for-boilerplate.msg');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);

is(slurp_body_only($outfile), slurp_body_only('t/expected/boilerplate-start-one'),
   "Message was modified as expected.");
clean_maildrop_dir();
$msg = make_msg('boilerplate_one_end', 'for-boilerplate.msg');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);

is(slurp_body_only($outfile), slurp_body_only('t/expected/boilerplate-end-one'),
   "Message was modified as expected.");
clean_maildrop_dir();

$msg = make_msg('boilerplate_all_start', 'for-boilerplate.msg');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);

is(slurp_body_only($outfile), slurp_body_only('t/expected/boilerplate-start-all'),
   "Message was modified as expected.");
clean_maildrop_dir();
$msg = make_msg('boilerplate_all_end', 'for-boilerplate.msg');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);

is(slurp_body_only($outfile), slurp_body_only('t/expected/boilerplate-end-all'),
   "Message was modified as expected.");
clean_maildrop_dir();

done_testing;
