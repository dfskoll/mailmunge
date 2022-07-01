use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

my $dir = maildrop_msg_dir();

sub dkim_result
{
        my ($file) = @_;
        if (-f '/usr/share/doc/perl-Mail-DKIM/dkimverify.pl') {
                # Rocky Linux
                open(IN, "perl /usr/share/doc/perl-Mail-DKIM/dkimverify.pl < " . $dir . "/" . $file . "|");
        } else {
                # Debian
                open(IN, "dkimproxy-verify < " . $dir . "/" . $file . "|");
        }
        while(<IN>) {
                chomp;
                if (/^verify result: (.*)/) {
                        my $result = $1;
                        close(IN);
                        return $result;
                }
        }
        close(IN);
        return "";
}

my $ans;

my $ip = get_smtp_server_ip();

my $msg;

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

my $result = dkim_result('dkim.msg');
is($result, 'pass', "Message's DKIM signature was correctly verified");

# Monkey with the message body
system('cp', "$dir/dkim.msg", "$dir/dkim-modified-body.msg");
open(OUT, ">>$dir/dkim-modified-body.msg");
print OUT "Some more stuff, what?\n";
close(OUIT);

$result = dkim_result('dkim-modified-body.msg');
is ($result, 'fail (body has been altered)', "Message's DKIM signature correctly failed to verify if body is altered");

# Monkey with the message headers
system("sed -e 's/^Subject: .*/Subject: I HAVE BEEN ALTERED/' < $dir/dkim.msg > $dir/dkim-modified-header.msg");

$result = dkim_result('dkim-modified-header.msg');
is ($result, 'fail (message has been altered)', "Message's DKIM signature correctly failed to verify if header is altered");

done_testing;
