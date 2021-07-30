use lib '.';
use Test::More;
use Test::Deep;

use Test::Mailmunge::RegressionUtils;

use MIME::Parser;
use JSON::Any;

my $ans;

my $ip = get_smtp_server_ip();

my $msg;
my $outfile = maildrop_msg_path();

clean_quarantine_dir();
clean_mta_queues();

my $msg = make_msg('rspamd', 'gtube-msg');
my $ans = smtp_send($ip, 'continue', 'continue@example.com', ['user1@example.com'], $msg);

cmp_deeply($ans, {
           code => 200,
           dsn => '2.0.0',
           txt => "OK",
           stage => 'quit'}, 'Got expected success');

wait_for_files($outfile);

my $parser = MIME::Parser->new();

my $entity = $parser->parse_open($outfile);

ok($entity, "Got a MIME Entity");
is(scalar($entity->parts), 2, "with 2 parts");

my $part = $entity->parts(1);
is($part->mime_type, 'application/json', 'Second part is application/json');
my $io = $part->bodyhandle->open("r");
my $json = '';
while(defined($_ = $io->getline())) {
        $json .= $_;
}
$io->close();
my $hash = JSON::Any->jsonToObj($json);

# The default rspamd setup on Red Hat is different from
# Debian, so we expect different results.
if (-f '/etc/redhat-release') {
        cmp_deeply($hash, {
                response => {delay => 0, status => 'CONTINUE', message => 'ok' },
                results => {
                        is_skipped => ignore(),
                        'message-id' => ignore(),
                        messages => { smtp_message => 'Gtube pattern' },
                        required_score => re('^\d+$'),
                        action => 'reject',
                        symbols => { GTUBE => { score => 0, name => 'GTUBE', metric_score => 0 }},
                        time_real => ignore(),
                        score => re('^\d+$'),
                        milter => ignore(),
                }},
                   "Got expected rspamd results");
} else {
        cmp_deeply($hash, {
                response => {delay => 0, status => 'CONTINUE', message => 'ok' },
                results => {
                        is_skipped => ignore(),
                        'message-id' => ignore(),
                        messages => { smtp_message => 'Gtube pattern' },
                        required_score => re('^\d+$'),
                        action => 'reject',
                        symbols => { GTUBE => { score => 0, name => 'GTUBE', metric_score => 0 }},
                        time_virtual => ignore(),
                        time_real => ignore(),
                        score => re('^\d+$'),
                }},
                   "Got expected rspamd results");
}




done_testing;
