use strict;
use warnings;

package Test::Mailmunge::Filter;
use base qw(Mailmunge::Filter::Compat);
use Mailmunge::Response;
use Mailmunge::Test::Rspamd;

use JSON::Any;

use MIME::Entity;

use Cwd;

use Mailmunge::Constants;

use Mailmunge::Action::Boilerplate;

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
        $self->action_tempfail($ctx, "I'm busy at the moment...") if ($ctx->subject eq 'begin-tempfail');
        return Mailmunge::Response->REJECT(message => 'I am not in the mood') if ($ctx->subject eq 'begin-reject');
        $self->action_discard($ctx) if ($ctx->subject eq 'begin-discard');

        $self->action_change_header($ctx, 'X-Foo', 'Foo has been CHANGED') if ($ctx->subject eq 'begin-chghdr');
        $self->action_delete_header($ctx, 'X-Foo') if ($ctx->subject eq 'begin-delhdr');
        $self->action_add_header($ctx, 'X-Foo', 'New-Foo') if ($ctx->subject eq 'begin-addhdr');
}

sub filter
{
        my ($self, $ctx, $entity, $fname, $extension, $type) = @_;
        $fname = lc($fname);
        if ($fname eq 'drop_with_warning.exe') {
                return $self->action_drop_with_warning($ctx, 'Attachments of type EXE are not accepted');
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
                $self->add_recipient($ctx, '<foobarbaz_added@example.org>');
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
                return Mailmunge::Response->REJECT(message => "I'm a-bouncin' ya!");
        }
        if ($subj =~ /\bdiscard\b/i) {
                $self->action_discard($ctx, "I'm a-discardin' ya!");
        }
        if ($subj =~ /\btempfail\b/i) {
                $self->action_tempfail($ctx, "I'm a-tempfailin' ya!");
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
