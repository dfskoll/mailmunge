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

$msg = make_msg('tempfail');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 451,
           dsn => '4.3.0',
           txt => "I'm a-tempfailin' ya!",
           stage => 'datasend'}, 'Got expected tempfail at datasend stage');
ok(! -r $outfile, "$outfile was not created");

$msg = make_msg('bounce');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 554,
           dsn => '5.7.1',
           txt => "I'm a-bouncin' ya!",
           stage => 'datasend'}, 'Got expected bounce at datasend stage');
ok(! -r $outfile, "$outfile was not created");

$msg = make_msg('discard');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');
ok(! -r $outfile, "$outfile was not created");

$msg = make_msg('quarantine');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

my $qdir = first_quarantined_msg();
ok($qdir, "A message was quarantined in $qdir");
if ($qdir) {
        is(`cat "$qdir/MSG.0"`, "Go to your room NOW, young message!\n", 'Got expected quarantine message');
        is(`cat "$qdir/RECIPIENTS"`, "<user1\@example.com>\n", 'Got expected quarantine recipients');
        is(`cat "$qdir/SENDER"`, "<continue\@example.com>\n", 'Got expected quarantine sender');
}
wait_for_files($outfile);

ok(-r $outfile, "... but message was still delivered to $outfile");

$msg = make_msg('smquarantine');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

my $hold = get_mta_hold_queue();
ok($hold && scalar(@$hold) == 1, 'Got a message in the "hold" queue');
clean_mta_queues();

# Virus-scan on EICAR test file
$msg = make_msg('virus', 'eicar-msg');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);
my $line = `grep ^X-Virus-Result: $outfile`;
chomp($line);
is ($line, 'X-Virus-Result: state=virus; data=Eicar-Signature', 'EICAR signature detected');

# Virus-scan on a clean message
$msg = make_msg('virus');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);
my $line = `grep ^X-Virus-Result: $outfile`;
chomp($line);
is ($line, 'X-Virus-Result: state=clean', 'No virus detected');

# Spam-scan on a GTUBE message
$msg = make_msg('spamassassin', 'gtube-msg');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);
my $line = `grep ^X-Spam-Result: $outfile`;
chomp($line);
like($line, qr/^X-Spam-Result: score=1\d\d\d.*tests=.*GTUBE/, 'SpamAssassin found the GTUBE test vector');

$msg = make_msg('continue', 'delete-part.msg');
$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

done_testing;
