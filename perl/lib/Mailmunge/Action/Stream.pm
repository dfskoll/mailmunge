package Mailmunge::Action::Stream;
use strict;
use warnings;

use base qw(Mailmunge::Action);
use Mailmunge::Constants;

sub stream_by_domain
{
        my ($self, $ctx) = @_;
        my $by_domain;
        my $seen;

        my $filter = $self->filter;

        foreach my $r (@{$ctx->recipients}) {

                # This is to guard against recipients being specified
                # multiple times in the original SMTP session.
                my $cr = $filter->canonical_email($r);
                next if $seen->{$cr};
                $seen->{$cr} = 1;

                push (@{$by_domain->{$filter->domain_of($r)}}, $r);
        }

        # Now build up the recipient groups array
        my @groups;
        foreach my $key (keys(%$by_domain)) {
                push(@groups, $by_domain->{$key});
        }
        return $self->stream_recipients($ctx, \@groups);
}

sub stream_by_recipient
{
        my ($self, $ctx) = @_;

        my $filter = $self->filter;

        # Make an array, each of whose elements is an arrayref
        # consisting of exactly one recipient
        my $seen;
        my @groups;
        foreach my $r (@{$ctx->recipients}) {

                # This is to guard against recipients being specified
                # multiple times in the original SMTP session.
                my $cr = $filter->canonical_email($r);
                next if $seen->{$cr};

                $seen->{$cr} = 1;
                push(@groups, [ $r ]);
        }

        return $self->stream_recipients($ctx, \@groups);
}

sub stream_recipients
{
        my ($self, $ctx, $recipient_groups) = @_;

        my $filter = $self->filter;

        return undef unless $ctx->in_message_context($self);

        # If there's only one group, don't stream
        if (scalar(@$recipient_groups) <= 1) {
                return 0;
        }

        # Validate that each original recipient appears
        # exactly once in $recipient_groups
        my $orig_recipients;
        foreach my $r (@{$ctx->recipients}) {
                $orig_recipients->{$filter->canonical_email($r)} = 1;
        }

        foreach my $g (@$recipient_groups) {
                foreach my $r (@$g) {
                        if (!exists($orig_recipients->{$filter->canonical_email($r)})) {
                                $filter->log($ctx, 'warning', "stream_recipients: $r not found in recipient list, or specified twice");
                                return undef;
                        }
                        delete $orig_recipients->{$filter->canonical_email($r)};
                }
        }
        # Any leftovers?
        my @leftovers = keys(%$orig_recipients);
        if (scalar(@leftovers)) {
                $filter->log($ctx, 'warning', "stream_recipients: Leftover recipients " . join(', ', @leftovers));
                return undef;
        }

        # OK, recipient groups are valid.  Now remail
        foreach my $g (@$recipient_groups) {
                $filter->log($ctx, 'info', 'stream_recipients: remailing to [' . join(', ', @$g) . ']');
        }

        foreach my $g (@$recipient_groups) {
                if (!$self->_stream_resend_message($ctx, $g)) {
                        return undef;
                }
        }
        return 1;
}

sub _stream_resend_message
{
        my ($self, $ctx, $group) = @_;

        my $filter = $self->filter;

        my $sm = Mailmunge::Constants->get_program_path('sendmail');
        if (!$sm) {
                $filter->log($ctx, 'warning', 'stream_recipients: cannot find sendmail executable');
                return undef;
        }

        my $pid = open(CHILD, '|-');
        if (!defined($pid)) {
                $filter->log($ctx, 'warning', "stream_recipients: fork failed: $!");
                return undef;
        }

        if ($pid) {
                # In the parent: Pipe mail message to child
                unless (open(IN, '<' . $filter->inputmsg)) {
                        $filter->log($ctx, 'warning', "stream_recipients: cannot read " . $filter->inputmsg . ": $!");
                        return undef;
                }
                print CHILD $filter->synthesize_received_header($ctx);
                print CHILD 'X-Mailmunge-Remailed: ' . $ctx->hostip . ' ' . $ctx->qid . "\n";
                my $in_headers = 1;
                while(<IN>) {
                        # Don't propagate any spurious X-Mailmunge-Remailed headers!
                        next if ($in_headers && $_ =~ /^X-Mailmunge-Remailed:/i);
                        $in_headers = 0 if ($_ eq "\n");
                        print CHILD;
                }
                close(IN);
                if (!close(CHILD)) {
                        if ($!) {
                                $filter->log($ctx, 'err', "stream_recipients: sendmail failure: $!");
                        } else {
                                $filter->log($ctx, 'err', "stream_recipients: sendmail non-zero exit status: $?");
                        }
                        return undef;
                }
                return 1;
        }

        # In the child ; invoke Sendmail

        # Avoid messing with Multiplexor communication
        open(STDOUT, '>&STDERR');

        my (@cmd);
        if ($ctx->sender eq '') {
                push(@cmd, '-f<>');
        } else {
                push(@cmd, '-f' . $ctx->sender);
        }
        push(@cmd, '-i');
        if ($filter->mta_is_sendmail()) {
                push (@cmd, '-Ac', '-odd');
        }
        push(@cmd, '--');
        push(@cmd, @$group);

        { exec($sm, @cmd); };
        $filter->log($ctx, 'err', "Could not execute $sm: $!");
        exit(1);
}

1;

__END__

=head1 NAME

Mailmunge::Action::Stream - stream mail by domain or recipient

=head1 ABSTRACT

This class implements methods that let you "stream" mail.  This lets
you apply different filtering rules per-recipient or per-domain.

=head1 SYNOPSIS

    package MyFilter;
    use base qw(Mailmunge::Filter);
    use Mailmunge::Action::Stream;

    sub filter_message {
        my ($self, $ctx) = @_;
        my $action = Mailmunge::Action::Stream->new($self);
        if ($action->stream_by_domain($ctx)) {
            $self->action_discard($ctx);
            return;
        }

        # Now all recipients are guaranteed to be in the same domain
    }

    my $filter = MyFilter->new();
    $filter->run();

    1;

=head1 METHODS

=head2 Mailmunge::Action::Stream-E<gt>new($filter)

Constructor.  Typically used within a filter file as followes:

        my $action = Mailmunge::Action::Stream->new($self);

=head2 stream_by_domain($ctx)

If all recipients are in the same domain, returns 0.  Otherwise, remails
copies of the message with each copy going to a group of recipients in the
same domain, and returns 1.

You typically want to discard the original message and skip the rest
of your filter processing if C<stream_by_domain> returns 1; the usual
idiom is:

        if ($action->stream_by_domain($ctx)) {
            $self->action_discard($ctx);
            return;
        }

The remailed messages will be filtered in a subsequent set of milter calls.

Returns undef if something went wrong.

=head2 stream_by_recipient($ctx)

If there is only one recipient, returns 0.  Otherwise, remails
copies of the message with each copy going to a single recipient.

As with C<stream_by_domain>, you typically want to discard the
original message and skip the rest of your filter processing if
C<stream_by_recipient> returns 1.

Returns undef if something went wrong.

=head2 stream_recipients($ctx, $groups)

This is the most general streaming function.  C<$groups> is an arrayref;
each element must be an arrayref of recipients.  Each recipient in
C<$ctx-E<gt>recipients> must appear in exactly one member of C<$groups>
and no additional recipients may appear.

If C<$groups> has only one element, this function does nothing and
returns 0.  Otherwise, it emails one copy of the message to each group
of recipients in C<$groups> and returns 1.

Returns undef if something went wrong.

=head1 STREAMING MECHANISM

When Mailmunge streams a message, it remails copies of it so the copies
can be re-scanned.

If your MTA is Sendmail, the copies are put in the Sendmail submission
queue and they appear in a subsequent set of filter callbacks
in an SMTP session originating from the localhost.

If your MTA is Postfix, the copies are re-injected, but are I<not> sent
via SMTP.  Instead, Postfix simulates an SMTP session.  If you want
to stream messages and are using Postfix, you I<must> set the
C<non_smtpd_milters> Postfix configuration variable to match
C<smtpd_milters>.  Otherwise, I<streamed messages will not be filtered!>

When C<Mailmunge::Action::Stream> remails a message, it adds a header
of the form:

    X-Mailmunge-Remailed: original_ip original_qid

where C<original_ip> is the value of C<$ctx-E<gt>hostip> and C<original_qid>
is C<$ctx-E<gt>qid> when the streaming function is invoked.

C<Mailmunge::Filter> looks for this header.  If the connecting IP is the
local host, the filter trusts the header and sets C<$ctx-E<gt>hostip>
and C<$ctx-E<gt>hostname> based on C<original_ip> from the header.  It
also logs a message:

    Resent from queue-ID: original_qid; original IP: original_ip

so the streamed messages can be correlated with the original message.

If the connecting host is I<not> the localhost, then C<Mailmunge::Filter>
ignores the X-Mailmunge-Remailed header.  Regardless of where a message
origintates, C<Mailmunge::Filter> deletes all X-Mailmunge-Remailed
headers so they don't show up downstream.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
