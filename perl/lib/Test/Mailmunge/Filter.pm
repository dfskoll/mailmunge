use strict;
use warnings;

package Test::Mailmunge::Filter;
use base qw(Mailmunge::Filter::Compat);
use Mailmunge::Response;
use Mailmunge::Test::Rspamd;
use Mailmunge::Action::DKIMSigner;
use Mail::DKIM::Signer;
use Mail::DKIM;

use JSON::Any;

use MIME::Entity;

use Cwd;

use Mailmunge::Constants;

use Mailmunge::Action::Boilerplate;

my $signing_key = 'MIIEpQIBAAKCAQEA56Vb3PSQuoISxMEPT7/FBST+4NgOmmB+a7O7HzbtKhMSbJRv+0uhmHz2/JiiDQn86HvPNGSlMz1CB/PsmjAh+d0u/dDW4SFyJIM/XewieneJ56ZPySgX77LiEs16x/yeE2VsVJgHCwxHHBVw70iRzzXQM5Jo+Y1ZGInDJlUoaL6TNd4uostSEWF+TV5LpUTAm4VyBrwxhEVBaroVo0whFW3FpiYCGN6EQiJfBEmiqT3h0LKUf5UxB0DC4GooU45ItXBn0xT7SyZK9DZy75bnUaJqtPs87bDf8aZIUipu3swn+1wHiUc3qMucuYi+UmhO2mtTMe/lyC79UfFPdp8zuQIDAQABAoIBABk4IIMywRr9FEwFdMRK7Yk82N7jxts5zCmvnJyuXy2oe+YEVxi1yDcQy9b+Sw4+WyF4cTuUBYRJlAnHnae/u8M3OGl7thk2ifW9sEVqcuqAXywwKBmPWuPGxuQjKM3jC9aywROIpaOnR4qgLvZuISm9AxjKRNF+eQe539wpg0e72sWT7yEpFmNjeNN+nLtvPIRPRI2IfNOrcNYxufBPJ8KA5PttQD41ACtJqcjJCfZGfW0UwiklTaME6VLrQ65jpYKXv7QIfuBmmaYZJ3juQg/QU+NJOHd6dz5O2ekE2JFWcKpmK5AYgulMyAejW+lQ0NEt6DAxXcAtAIIID4n/wI0CgYEA9s11BISoJ1QMM3rbeKVvyunEnRClaoaShKbJptS9sDjlO7hHb2tLEMqHH0N/KFN6BL/vXtMpsCBOP3GPeaKoAAUH3M8yOb/MWyB+P126Mit/ENnoyfr0ZYgnGGDViXeO7UoxumtBSxo7W0M5/ZJVJx47p0uzqoDTr/y8i29ZWm8CgYEA8EdN+ndlz7JAXelQjIfHwgIhiC+1vw5WL6DvvxFlf/qc3XHu8iMJX5RjRkReBfd1J5o+/DKzPACCfENiEekA1p6jhKweEWpux/CcDSz6j0H3cfsJapAtgiuQwqiTqgQjymUkfXkngclPKJUmZ5n7ChlNp02euQROilOklOFyCFcCgYEAzYOG9s00bRNq2Y9rpIo2jkSdaaEL7anD5lwwvRCYKF8oW9N3AMvahU/wttLw1va0O7JMNK0oILa2EdSRgds1hFasFm4ex8Hz/MoQ9tkojFB2DeU3GMI1szpuO7me90qspOHMiQx5IX3lgXh4mLO63skpKYU7Rjbij8CojH+ba1cCgYEA5y+kTras5h8bIYDIuL44LGpCezd0hqSztlYB93Q0leO7JLJn9uBRN36d2lETqmgDeBxIN/5MSBIxeoCXDqaC4P14VcIJmDYw6v2OGHtLhaUyAaBJ2hdpQhLK0RDEK1SaXzXb20JECfN4z5Jahlo4menotm3PpzMGor+B3qHgRzcCgYEAsBfgwkno24K43NXPf5SqhDvf+mQmtoxuTT4oxa4jDve4sxNTYh7qyX8iRCRZmD2m47bxETqXAznclVSNOMVOc+rOx+oxEVQ1neMvFWq6DWf312NJwDzZbhLcHR+gTbNSulnxbxBxC/V7mJd5+ujTxZxlCsSbO+4EyH0dRwNQ9po=';

sub log_identifier { return 'mailmunge-test-filter-dont-panic'; }

sub initialize
{
        my $cwd = getcwd();
        Mailmunge::Constants->_set('Path:SPOOLDIR', $cwd);
        Mailmunge::Constants->_set('Path:QUARANTINEDIR', "$cwd/quarantine");
}


sub log
{
        my ($self, $ctx, $level, $msg) = @_;
        my $qid = $ctx;
        $qid = $ctx->qid if ref($ctx);

        push(@{$self->{TEST_LOGS}}, [$qid, $level, $msg]);
}

sub filter_relay
{
        my ($self, $ctx) = @_;

        my $ip = $ctx->hostip;
        return Mailmunge::Response->CONTINUE() if ($ip eq '10.0.0.1');
        return Mailmunge::Response->TEMPFAIL(message => 'Whoops') if ($ip eq '10.0.0.2');
        return Mailmunge::Response->REJECT(message => 'GO AWAY')   if ($ip eq '10.0.0.3');
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING(message => 'I love you')   if ($ip eq '10.0.0.4');
        return Mailmunge::Response->TEMPFAIL(message => 'Case not covered');
}

sub filter_helo
{
        my ($self, $ctx) = @_;
        my $helo = $ctx->helo;

        return Mailmunge::Response->CONTINUE() if ($helo eq 'continue');
        return Mailmunge::Response->TEMPFAIL() if ($helo eq 'tempfail');
        return Mailmunge::Response->REJECT()   if ($helo eq 'reject');
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($helo eq 'accept_and_no_more_filtering');
        return Mailmunge::Response->TEMPFAIL(message => 'Case not covered');
}

sub filter_sender
{
        my ($self, $ctx) = @_;
        my $sender = $ctx->sender;

        return Mailmunge::Response->CONTINUE() if ($sender =~ /continue/i);
        return Mailmunge::Response->TEMPFAIL() if ($sender =~ /tempfail/i);
        return Mailmunge::Response->REJECT()   if ($sender =~ /reject/i);
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($sender =~ /accept_and_no_more_filtering/i);
        return Mailmunge::Response->TEMPFAIL(message => 'Case not covered');
}
sub filter_recipient
{
        my ($self, $ctx) = @_;
        my $recipient = $ctx->recipients->[0];

        return Mailmunge::Response->CONTINUE() if ($recipient =~ /continue/i);
        return Mailmunge::Response->TEMPFAIL() if ($recipient =~ /tempfail/i);
        return Mailmunge::Response->REJECT()   if ($recipient =~ /reject/i);
        return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING()   if ($recipient =~ /accept_and_no_more_filtering/i);
        return Mailmunge::Response->TEMPFAIL(message => 'Case not covered');
}

sub filter_begin
{
        my ($self, $ctx) = @_;
        $ctx->action_tempfail("I'm busy at the moment...") if ($ctx->subject eq 'begin-tempfail');
        return Mailmunge::Response->REJECT(message => 'I am not in the mood') if ($ctx->subject eq 'begin-reject');
        $ctx->action_discard() if ($ctx->subject eq 'begin-discard');

        $ctx->action_change_header('X-Foo', 'Foo has been CHANGED') if ($ctx->subject eq 'begin-chghdr');
        $ctx->action_delete_header('X-Foo') if ($ctx->subject eq 'begin-delhdr');
        $ctx->action_add_header('X-Foo', 'New-Foo') if ($ctx->subject eq 'begin-addhdr');
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
                return $self->action_accept($ctx, "I reluctantly accepted warn.txt");
        }
}

sub filter_end
{
        my($self, $ctx) = @_;

        my $subj = $ctx->subject;

        if ($subj =~ /\bcopy-this-email\b/) {
                my $fh = $self->inputmsg_fh();
                if ($fh) {
                        if (open(OUT, '>COPIED_EMAIL')) {
                                while(<$fh>) {
                                        print OUT;
                                }
                                close(OUT);
                        }
                        close($fh);
                }
        }
        if ($subj =~ /\brspamd\b/i) {
                my $test = Mailmunge::Test::Rspamd->new($self);
                my $ans = $test->rspamd_check($ctx, '127.0.0.1',
                                                  $ENV{RSPAMD_PORT} || 11333,
                                              20);
                # Convert objects to hashes in $ans
                if (ref($ans) eq 'HASH') {
                        foreach my $k (keys(%$ans)) {
                                my $v = $ans->{$k};
                                $ans->{$k} = { %$v };
                        }
                }
                open(OUT, '>RSPAMD_RESULTS');
                print OUT JSON::Any->objToJson($ans);
                print OUT "\n";
                close(OUT);
        }
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
                $ctx->action_change_header('Subject', "[New subject] " . $subj);
        }
        if ($subj =~ /\bdelhdr\b/i) {
                $ctx->action_delete_header('X-Delete-Me');
        }
        if ($subj =~ /\bchghdr\b/i) {
                $ctx->action_change_header('X-Change-Me', 'You are changed!');
        }
        if ($subj =~ /\bdelallhdrs\b/i) {
                $ctx->action_delete_all_headers('X-Delete-Us-All');
        }
        if ($subj =~ /\bchgsender\b/i) {
                $ctx->change_sender('<changed_sender@example.org>');
        }
        if ($subj =~ /\baddrcpt\b/i) {
                $ctx->add_recipient('<foobarbaz_added@example.org>');
        }
        if ($subj =~ /\bdelrcpt\b/i) {
                $ctx->delete_recipient($ctx->recipients->[0]);
        }
        if ($subj =~ /\baddhdr\b/i) {
                $ctx->action_add_header('X-Added', 'I am new!');
        }
        if ($subj =~ /\bsmquarantine\b/i) {
                $ctx->action_sm_quarantine('You are evil and bad so I am quarantining you');
        }
        if ($subj =~ /\bquarantine\b/i) {
                $ctx->action_quarantine_entire_message("Go to your room NOW, young message!");
        }
        if ($subj =~ /\bbounce\b/i) {
                return Mailmunge::Response->REJECT(message => "I'm a-bouncin' ya!");
        }
        if ($subj =~ /\bdiscard\b/i) {
                $ctx->action_discard("I'm a-discardin' ya!");
        }
        if ($subj =~ /\btempfail\b/i) {
                $ctx->action_tempfail("I'm a-tempfailin' ya!");
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

__END__

=head1 NAME

Test::Mailmunge::Filter - A Mailmunge filter for use with unit tests.
Read the code to see how it works.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
