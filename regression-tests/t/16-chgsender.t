use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg;
my $file = maildrop_msg_path();

clean_maildrop_dir();
clean_mta_queues();

$msg = make_msg('chgsender');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($file);

my $entity = slurp_as_mime_entity($file);

is($entity->mime_type, 'text/plain', 'MIME type was left alone');

if (server_running_postfix()) {
        # Sendmail does not add a Return-Path: header
        is($entity->head->get('Return-Path'), '<changed_sender@example.org>' . "\n",
           'Envelope sender was changed in Return-Path:.');
}

open(IN, '<', $file);
my $line = <IN>;
like($line, qr/From changed_sender\@example\.org /, 'Envelope sender was changed');
done_testing;
