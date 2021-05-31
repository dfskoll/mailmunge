use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg = make_msg('stream_by_domain', 'generic-msg', 'stream-%DEST%');

clean_maildrop_dir();

my $ans = smtp_send($ip, 'continue', 'continue@example.com',
                    ['user1@example.com', 'user2@example.com',
                     'user3@example.org', 'user4@example.net'],
                    $msg);
cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

my $dir = maildrop_msg_dir();
wait_for_files("$dir/stream-user1",
               "$dir/stream-user2",
               "$dir/stream-user3",
               "$dir/stream-user4");

my $q1 = `grep ^X-Last-QID: $dir/stream-user1 | awk '{print \$2}'`;
my $q2 = `grep ^X-Last-QID: $dir/stream-user2 | awk '{print \$2}'`;
my $q3 = `grep ^X-Last-QID: $dir/stream-user3 | awk '{print \$2}'`;
my $q4 = `grep ^X-Last-QID: $dir/stream-user4 | awk '{print \$2}'`;

is($q1, $q2, 'user1 and user2 were sent in one batch');
isnt($q1, $q3, 'user1 and user3 were sent in different batches');
isnt($q1, $q4, 'user1 and user4 were sent in different batches');
isnt($q3, $q4, 'user3 and user4 were sent in different batches');

$msg = make_msg('stream_by_recipient', 'generic-msg', 'stream-%DEST%');

clean_maildrop_dir();
my $ans = smtp_send($ip, 'continue', 'continue@example.com',
                    ['user1@example.com', 'user2@example.com',
                     'user3@example.org', 'user4@example.net'],
                    $msg);
cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

my $dir = maildrop_msg_dir();
wait_for_files("$dir/stream-user1",
               "$dir/stream-user2",
               "$dir/stream-user3",
               "$dir/stream-user4");

my $q1 = `grep ^X-Last-QID: $dir/stream-user1 | awk '{print \$2}'`;
my $q2 = `grep ^X-Last-QID: $dir/stream-user2 | awk '{print \$2}'`;
my $q3 = `grep ^X-Last-QID: $dir/stream-user3 | awk '{print \$2}'`;
my $q4 = `grep ^X-Last-QID: $dir/stream-user4 | awk '{print \$2}'`;

isnt($q1, $q2, 'user1 and user2 were sent in different batches');
isnt($q1, $q3, 'user1 and user3 were sent in different batches');
isnt($q1, $q4, 'user1 and user4 were sent in different batches');
isnt($q2, $q3, 'user2 and user3 were sent in different batches');
isnt($q2, $q4, 'user2 and user4 were sent in different batches');
isnt($q3, $q4, 'user3 and user4 were sent in different batches');


done_testing;
1;


