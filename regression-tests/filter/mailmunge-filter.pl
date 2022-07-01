#!/usr/bin/env perl
use strict;
use warnings;

package MyFilter;
use base qw(Mailmunge::Filter::Compat);
use Mailmunge::Response;
use Mailmunge::Constants;
use Mailmunge::Test::SpamAssassin;
use Mailmunge::Test::Rspamd;
use Mailmunge::Test::Greylist;
use Mailmunge::Action::Stream;
use Mailmunge::Action::Boilerplate;
use Mailmunge::Action::DKIMSigner;
use Mail::DKIM::Signer;
use Mail::DKIM;

use JSON::Any;
use DBI;

use MIME::Entity;
use File::VirusScan;

my $dbh;
my $db_file = ':memory:';

my $signing_key = 'MIIEpQIBAAKCAQEA56Vb3PSQuoISxMEPT7/FBST+4NgOmmB+a7O7HzbtKhMSbJRv+0uhmHz2/JiiDQn86HvPNGSlMz1CB/PsmjAh+d0u/dDW4SFyJIM/XewieneJ56ZPySgX77LiEs16x/yeE2VsVJgHCwxHHBVw70iRzzXQM5Jo+Y1ZGInDJlUoaL6TNd4uostSEWF+TV5LpUTAm4VyBrwxhEVBaroVo0whFW3FpiYCGN6EQiJfBEmiqT3h0LKUf5UxB0DC4GooU45ItXBn0xT7SyZK9DZy75bnUaJqtPs87bDf8aZIUipu3swn+1wHiUc3qMucuYi+UmhO2mtTMe/lyC79UfFPdp8zuQIDAQABAoIBABk4IIMywRr9FEwFdMRK7Yk82N7jxts5zCmvnJyuXy2oe+YEVxi1yDcQy9b+Sw4+WyF4cTuUBYRJlAnHnae/u8M3OGl7thk2ifW9sEVqcuqAXywwKBmPWuPGxuQjKM3jC9aywROIpaOnR4qgLvZuISm9AxjKRNF+eQe539wpg0e72sWT7yEpFmNjeNN+nLtvPIRPRI2IfNOrcNYxufBPJ8KA5PttQD41ACtJqcjJCfZGfW0UwiklTaME6VLrQ65jpYKXv7QIfuBmmaYZJ3juQg/QU+NJOHd6dz5O2ekE2JFWcKpmK5AYgulMyAejW+lQ0NEt6DAxXcAtAIIID4n/wI0CgYEA9s11BISoJ1QMM3rbeKVvyunEnRClaoaShKbJptS9sDjlO7hHb2tLEMqHH0N/KFN6BL/vXtMpsCBOP3GPeaKoAAUH3M8yOb/MWyB+P126Mit/ENnoyfr0ZYgnGGDViXeO7UoxumtBSxo7W0M5/ZJVJx47p0uzqoDTr/y8i29ZWm8CgYEA8EdN+ndlz7JAXelQjIfHwgIhiC+1vw5WL6DvvxFlf/qc3XHu8iMJX5RjRkReBfd1J5o+/DKzPACCfENiEekA1p6jhKweEWpux/CcDSz6j0H3cfsJapAtgiuQwqiTqgQjymUkfXkngclPKJUmZ5n7ChlNp02euQROilOklOFyCFcCgYEAzYOG9s00bRNq2Y9rpIo2jkSdaaEL7anD5lwwvRCYKF8oW9N3AMvahU/wttLw1va0O7JMNK0oILa2EdSRgds1hFasFm4ex8Hz/MoQ9tkojFB2DeU3GMI1szpuO7me90qspOHMiQx5IX3lgXh4mLO63skpKYU7Rjbij8CojH+ba1cCgYEA5y+kTras5h8bIYDIuL44LGpCezd0hqSztlYB93Q0leO7JLJn9uBRN36d2lETqmgDeBxIN/5MSBIxeoCXDqaC4P14VcIJmDYw6v2OGHtLhaUyAaBJ2hdpQhLK0RDEK1SaXzXb20JECfN4z5Jahlo4menotm3PpzMGor+B3qHgRzcCgYEAsBfgwkno24K43NXPf5SqhDvf+mQmtoxuTT4oxa4jDve4sxNTYh7qyX8iRCRZmD2m47bxETqXAznclVSNOMVOc+rOx+oxEVQ1neMvFWq6DWf312NJwDzZbhLcHR+gTbNSulnxbxBxC/V7mJd5+ujTxZxlCsSbO+4EyH0dRwNQ9po=';

sub initialize
{
        # Create the greylist database
        unlink($db_file);

        $dbh = DBI->connect("dbi:SQLite:dbname=$db_file");
        $dbh->do(q{CREATE TABLE greylist(hash TEXT PRIMARY KEY NOT NULL, last_seen INTEGER)});
        $dbh->do(q{CREATE TABLE ips_known_to_retry(ip TEXT PRIMARY KEY NOT NULL, last_seen INTEGER)});
}

my $filter = MyFilter->new();
$filter->run();
exit(0);

# Create virus scanner
my $scanner;

sub get_virus_scanner
{
        if (!$scanner) {
                $scanner = File::VirusScan->new({
                        engines => {
                                '-Daemon::ClamAV::Clamd' => {
                                        socket_name => '/var/run/clamav/clamd.ctl',
                                },
                        },
                                                });
        }
        return $scanner;
}


sub filter_helo
{
        my ($self, $ctx) = @_;
        my $helo = $ctx->helo;

        return Mailmunge::Response->CONTINUE() if ($helo eq 'continue');
        return Mailmunge::Response->TEMPFAIL(message => "I tempfail your HELO") if ($helo eq 'tempfail');
        return Mailmunge::Response->REJECT(message => "I reject your HELO")   if ($helo eq 'reject');
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($helo eq 'accept_and_no_more_filtering');
        return Mailmunge::Response->CONTINUE();
}

sub filter_sender
{
        my ($self, $ctx) = @_;
        my $sender = $ctx->sender;

        return Mailmunge::Response->CONTINUE() if ($sender =~ /continue/i);
        return Mailmunge::Response->TEMPFAIL(message => "I tempfail your sender") if ($sender =~ /tempfail/i);
        return Mailmunge::Response->REJECT(message => "I reject your sender")   if ($sender =~ /reject/i);
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($sender =~ /accept_and_no_more_filtering/i);
        return Mailmunge::Response->CONTINUE();
}
sub filter_recipient
{
        my ($self, $ctx) = @_;
        my $recipient = $ctx->recipients->[0];

        if ($ctx->sender =~ /greylist/i) {
                my $gl = Mailmunge::Test::Greylist->new($self);
                return $gl->evaluate($dbh, 0, 0, $ctx->hostip, $ctx->sender, $ctx->recipients->[0]);
        }

        return Mailmunge::Response->CONTINUE() if ($recipient =~ /continue/i);
        return Mailmunge::Response->TEMPFAIL(message => "I tempfail your recipient") if ($recipient =~ /tempfail/i);
        return Mailmunge::Response->REJECT(message => "I reject your recipient")   if ($recipient =~ /reject/i);
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($recipient =~ /accept_and_no_more_filtering/i);
        return Mailmunge::Response->CONTINUE();
}

sub filter_begin
{
        my ($self, $ctx) = @_;

        my $subj = $ctx->subject;
        $self->log($ctx, 'info', "Subject=$subj");
        if ($subj =~ /\bstream_by_domain\b/) {
                my $action = Mailmunge::Action::Stream->new($self);
                my $ans = $action->stream_by_domain($ctx);
                if ($ans) {
                        return Mailmunge::Response->DISCARD();
                } else {
                        $self->log($ctx, 'info', 'post stream_by_domain: Recipient list: ' . join(', ', @{$ctx->recipients}));
                        $self->log($ctx, 'info', 'post stream_by_domain: Hostname: ' . $ctx->hostname);
                        $self->log($ctx, 'info', 'post stream_by_domain: Hostip: ' . $ctx->hostip);
                }
        }
        if ($subj =~ /\bstream_by_recipient\b/) {
                my $action = Mailmunge::Action::Stream->new($self);
                my $ans = $action->stream_by_recipient($ctx);
                if ($ans) {
                        return Mailmunge::Response->DISCARD();
                } else {
                        $self->log($ctx, 'info', 'post stream_by_recipient: Recipient list: ' . join(', ', @{$ctx->recipients}));
                        $self->log($ctx, 'info', 'post stream_by_recipient: Hostname: ' . $ctx->hostname);
                        $self->log($ctx, 'info', 'post stream_by_recipient: Hostip: ' . $ctx->hostip);
                }
        }

        return Mailmunge::Response->TEMPFAIL(message => "I'm busy at the moment...") if ($subj eq 'begin-tempfail');
        return Mailmunge::Response->REJECT(message => 'I am not in the mood')        if ($subj eq 'begin-reject');
        return Mailmunge::Response->DISCARD()                                        if ($subj eq 'begin-discard');

        $self->action_change_header($ctx, 'X-Foo', 'Foo has been CHANGED') if ($subj eq 'begin-chghdr');
        $self->action_delete_header($ctx, 'X-Foo') if ($subj eq 'begin-delhdr');
        $self->action_add_header($ctx, 'X-Foo', 'New-Foo') if ($subj eq 'begin-addhdr');
        return 0;
}

sub filter
{
        my ($self, $ctx, $entity, $fname, $extension, $type) = @_;
        $fname = lc($fname);
        if ($fname eq 'drop_with_warning.exe') {
                return $self->action_drop($ctx, 'Attachments of type EXE are not accepted');
        }
        if ($fname eq 'replace_with_warning.exe') {
                return $self->action_replace_with_warning($ctx, "Replaced $fname");
        }
        if ($fname eq 'drop.exe') {
                return $self->action_drop($ctx);
        }
        if ($fname eq 'warn.txt') {
                return $self->action_accept_with_warning($ctx, "I reluctantly accepted warn.txt");
        }
        return 0;
}

sub filter_end
{
        my($self, $ctx) = @_;

        my $subj = $ctx->subject;

        # Add a header giving ultimate queue ID
        $self->action_change_header($ctx, 'X-Last-QID', $ctx->qid);
        if ($subj =~ /\baddentity\b/i) {
                my $entity = MIME::Entity->build(Type => 'text/plain',
                                                 Top => 0,
                                                 'X-Mailer' => undef,
                                                 Encoding => '-suggest',
                                                 Data => [ "A new entity, woop woop!\n" ]);
                $self->action_add_entity($ctx, $entity);
        }

        if ($subj =~ /\baddpart\b/i) {
                $self->action_add_part($ctx, 'text/html', '-suggest', "<html><head><title>Foo</title></head><body><p>Wookie</p></body></html>\n");
        }
        if ($subj =~ /\bchgsub\b/i) {
                $self->action_change_header($ctx, 'Subject', "[New subject] " . $subj);
        }
        if ($subj =~ /\bdelhdr\b/i) {
                $self->action_delete_header($ctx, 'X-Delete-Me');
        }
        if ($subj =~ /\bchghdr\b/i) {
                $self->action_change_header($ctx, 'X-Change-Me', 'You are changed!');
        }
        if ($subj =~ /\bdelallhdrs\b/i) {
                $self->action_delete_all_headers($ctx, 'X-Delete-Us-All');
        }
        if ($subj =~ /\bchgsender\b/i) {
                $self->change_sender($ctx, '<changed_sender@example.org>');
        }
        if ($subj =~ /\baddrcpt\b/i) {
                $self->add_recipient($ctx, '<user5@example.org>');
        }
        if ($subj =~ /\bdelrcpt\b/i) {
                $self->delete_recipient($ctx, $ctx->recipients->[0]);
        }
        if ($subj =~ /\baddhdr\b/i) {
                $self->action_add_header($ctx, 'X-Added', 'I am new!');
        }
        if ($subj =~ /\bsmquarantine\b/i) {
                $self->action_sm_quarantine($ctx, 'You are evil and bad so I am quarantining you');
        }
        if ($subj =~ /\bquarantine\b/i) {
                $self->action_quarantine_entire_message($ctx, "Go to your room NOW, young message!");
        }
        if ($subj =~ /\bbounce\b/i) {
                $self->action_bounce($ctx, "I'm a-bouncin' ya!");
        }
        if ($subj =~ /\bdiscard\b/i) {
                $self->action_discard($ctx, "I'm a-discardin' ya!");
        }
        if ($subj =~ /\btempfail\b/i) {
                return Mailmunge::Response->TEMPFAIL(message => "I'm a-tempfailin' ya!");
        }
        if ($subj =~ /\brspamd\b/i) {
                my $test = Mailmunge::Test::Rspamd->new($self);
                my $ans = $test->rspamd_check($ctx, '127.0.0.1', 11333);
                if ($ans) {
                        # Convert objects to hashes in $ans
                        if (ref($ans) eq 'HASH') {
                                foreach my $k (keys(%$ans)) {
                                        my $v = $ans->{$k};
                                        $ans->{$k} = { %$v };
                                }
                        }
                        # Add rspamd results as a JSON part to original message
                        $self->action_add_part($ctx, 'application/json', '-suggest', JSON::Any->objToJson($ans));
                }
        }
        if ($subj =~ /\bspamassassin\b/i) {
                my $test = Mailmunge::Test::SpamAssassin->new($self);
                my $status = $test->spam_assassin_status($ctx, 1);
                if ($status) {
                        $self->action_add_header($ctx, 'X-Spam-Result', 'score=' . $status->get_score() . '; tests=' . $status->get_names_of_tests_hit());
                        $status->finish();
                }
        }
        if ($subj =~ /\bvirus\b/i) {
                # Do virus-scanning
                my $s = $self->get_virus_scanner();
                my $resultset = $s->scan($self->inputmsg_absolute($ctx));
                my @contents = $resultset->contents();
                my $result = $contents[0];
                my $state = $result->get_state();
                my $data = $result->get_data();
                if ($data) {
                        $data = "; data=$data";
                } else {
                        $data = '';
                }
                $self->action_add_header($ctx, 'X-Virus-Result', "state=$state$data");
        }
        if ($subj =~ /\bboilerplate_one_start\b/) {
                my $action = Mailmunge::Action::Boilerplate->new($self);
                $action->add_text_boilerplate($ctx, $ctx->mime_entity, "Some plaintext boilerplate at start - one part only", 1, 0);
                $action->add_html_boilerplate($ctx, $ctx->mime_entity, "<p>Some <b>HTML</b> boilerplate at start - one part only</p>", 1, 0);
        }
        if ($subj =~ /\bboilerplate_one_end\b/) {
                my $action = Mailmunge::Action::Boilerplate->new($self);
                $action->add_text_boilerplate($ctx, $ctx->mime_entity, "Some plaintext boilerplate at end - one part only", 0, 0);
                $action->add_html_boilerplate($ctx, $ctx->mime_entity, "<p>Some <b>HTML</b> boilerplate at end - one part only</p>", 0, 0);
        }
        if ($subj =~ /\bboilerplate_all_start\b/) {
                my $action = Mailmunge::Action::Boilerplate->new($self);
                $action->add_text_boilerplate($ctx, $ctx->mime_entity, "Some plaintext boilerplate at start - all parts", 1, 1);
                $action->add_html_boilerplate($ctx, $ctx->mime_entity, "<p>Some <b>HTML</b> boilerplate at start - all parts</p>", 1, 1);
        }
        if ($subj =~ /\bboilerplate_all_end\b/) {
                my $action = Mailmunge::Action::Boilerplate->new($self);
                $action->add_text_boilerplate($ctx, $ctx->mime_entity, "Some plaintext boilerplate at end - all parts", 0, 1);
                $action->add_html_boilerplate($ctx, $ctx->mime_entity, "<p>Some <b>HTML</b> boilerplate at end - all parts</p>", 0, 1);
        }
        return 0;
}

sub filter_wrapup
{
        my($self, $ctx) = @_;

        my $subj = $ctx->subject;

        if ($subj =~ /\bdkim_sign\b/) {
                my $signer = Mail::DKIM::Signer->new(
                        Algorithm => 'rsa-sha256',
                        Method    => 'relaxed',
                        Domain    => 'test.mailmunge.org',
                        Selector  => 'testing',
                        Key       => Mail::DKIM::PrivateKey->load(Data => $signing_key));
                my $action = Mailmunge::Action::DKIMSigner->new($self);
                $action->add_dkim_signature($ctx, $signer);
        }
        return 0;
}

1;
