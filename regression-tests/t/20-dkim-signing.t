use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $ans;

my $ip = get_smtp_server_ip();

my $msg;
my $dir = maildrop_msg_dir();

clean_quarantine_dir();
clean_mta_queues();

$msg = make_msg('boilerplate_one_start dkim_sign', 'for-dkim-signing.msg');

$ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files("$dir/dkim.msg");

if (-f '/usr/share/doc/perl-Mail-DKIM/dkimverify.pl') {
        # Rocky Linux
        open(IN, "perl /usr/share/doc/perl-Mail-DKIM/dkimverify.pl < $dir/dkim.msg|");
} else {
        # Debian
        open(IN, "dkimproxy-verify < $dir/dkim.msg|");
}

my $passed = 0;
while(<IN>) {
        $passed = 1 if (/verify result: pass/);
}
close(IN);
ok($passed, "Message's DKIM signature was correctly verified");

# Monkey with the message
open(OUT, ">>$dir/dkim.msg");
print OUT "Some more stuff, what?\n";
close(OUIT);

$passed = 1;
if (-f '/usr/share/doc/perl-Mail-DKIM/dkimverify.pl') {
        # Rocky Linux
        open(IN, "perl /usr/share/doc/perl-Mail-DKIM/dkimverify.pl < $dir/dkim.msg|");
} else {
        # Debian
        open(IN, "dkimproxy-verify < $dir/dkim.msg|");
}

while(<IN>) {
        $passed = 0 if (/verify result: fail .body has been altered/);
}
close(IN);
ok(!$passed, "Message's DKIM signature correctly failed to verify if body is altered");

done_testing;
