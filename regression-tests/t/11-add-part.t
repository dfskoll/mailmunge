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

$msg = make_msg('addpart');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($file);

my $entity = slurp_as_mime_entity($file);

is($entity->mime_type, 'multipart/mixed', 'Message was changed to multipart/mixed');
is(scalar($entity->parts), 2, 'There are two parts');
my $part = $entity->parts(1);
is ($part->mime_type, 'text/html', 'text/html part was added');
my $body = $part->bodyhandle;
is ($body->as_string, "<html><head><title>Foo</title></head><body><p>Wookie</p></body></html>\n", 'Got expected new part');

done_testing;
