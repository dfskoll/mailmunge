use strict;
use warnings;

package Mailmunge::Response;
use base qw(Mailmunge::Base);

use Carp;

my @accessors = qw(
    code
    delay
    dsn
    message
    status
);

sub status
{
        my ($self, $newstatus) = @_;
        if (defined($newstatus)) {
                if ($newstatus eq 'ACCEPT_AND_NO_MORE_FILTERING' ||
                    $newstatus eq 'DISCARD' ||
                    $newstatus eq 'CONTINUE' ||
                    $newstatus eq 'REJECT' ||
                    $newstatus eq 'TEMPFAIL') {
                        $self->{status} = $newstatus;
                } else {
                        croak("Illegal status $newstatus");
                }
        }
        return $self->{status};
}

sub new
{
        my $class = shift;
        my $self = bless {}, $class;
        while(scalar(@_)) {
                my $key = shift;
                my $val = shift;
                $self->$key($val);
        }
        $self->{delay}  = 0          unless defined($self->{delay}) && $self->{delay} =~ /^\d+$/;
        $self->{message} = ''        unless defined($self->{message});
        $self->{status} = 'CONTINUE' unless defined($self->{status});
        return $self;
}

sub CONTINUE
{
        my $class = shift;
        return $class->new(status => 'CONTINUE', message => 'ok', @_);
}

sub ACCEPT_AND_NO_MORE_FILTERING
{
        my $class = shift;
        return $class->new(status => 'ACCEPT_AND_NO_MORE_FILTERING', message => 'ok', @_);
}

sub DISCARD
{
        my $class = shift;
        return $class->new(status => 'DISCARD', @_);
}
sub TEMPFAIL
{
        my $class = shift;
        return $class->new(status => 'TEMPFAIL', @_);
}

sub REJECT
{
        my $class = shift;
        return $class->new(status => 'REJECT', @_);
}


sub fix_code_dsn
{
        my ($self) = @_;
        if ($self->is_success_or_discard) {
                $self->{code} = 250 unless (defined($self->{code}) and $self->{code} =~ /^2\d\d$/);
                $self->{dsn} = "2.1.0" unless (defined($self->{dsn}) and $self->{dsn} =~ /^2\.\d{1,3}\.\d{1,3}$/);
        } elsif ($self->is_tempfail) {
                $self->{code} = 451 unless (defined($self->{code}) and $self->{code} =~ /^4\d\d$/);
                $self->{dsn} = "4.3.0" unless (defined($self->{dsn}) and $self->{dsn} =~ /^4\.\d{1,3}\.\d{1,3}$/);
        } elsif ($self->is_reject) {
                $self->{code} = 554 unless (defined($self->{code}) and $self->{code} =~ /^5\d\d$/);
                $self->{dsn} = "5.7.1" unless (defined($self->{dsn}) and $self->{dsn} =~ /^5\.\d{1,3}\.\d{1,3}$/);
        }
}

sub is_tempfail
{
        my ($self) = @_;
        return 1 if $self->{status} eq 'TEMPFAIL';
        return 0;
}

sub is_discard
{
        my ($self) = @_;
        return 1 if $self->{status} eq 'DISCARD';
        return 0;
}

sub is_reject
{
        my ($self) = @_;
        return 1 if $self->{status} eq 'REJECT';
        return 0;
}

sub is_success
{
        my ($self) = @_;
        return 1 if ($self->{status} eq 'CONTINUE' || $self->{status} eq 'ACCEPT_AND_NO_MORE_FILTERING');
        return 0;
}

sub is_success_or_discard
{
        my ($self) = @_;
        return 1 if ($self->{status} eq 'CONTINUE' || $self->{status} eq 'ACCEPT_AND_NO_MORE_FILTERING' || $self->{status} eq 'DISCARD');
        return 0;
}

__PACKAGE__->make_accessors(@accessors);

1;

__END__

=head1 NAME

Mailmunge::Response - encapsulates response to send back to Milter.

=head1 ABSTRACT

Mailmunge::Response holds all of the information needed to reply to
an SMTP connection request or SMTP command such as HELO, MAIL From: and
RCPT To:

=head1 SYNOPSIS

    use Mailmunge::Response;

    sub filter_sender {
        my ($self, $ctx) = @_;
        # Everything's OK
        return Mailmunge::Response->new(status => 'CONTINUE');

        # Reject
        return Mailmunge::Response->new(status => 'REJECT',
                                        message => $ctx->sender . ' is unwelcome');

=head1 CLASS METHODS

=head2 Mailmunge::Response->new($key1 => $val1 [, $key2 => $val2...])

Creates a new Mailmunge::Response object.  Arguments are a series
of C<key =E<gt> val> pairs.  Possible keys are:

=over 4

=item status

The status to return.  This is one of the following strings:

=over 4

=item CONTINUE

Accept the SMTP command with a 2xx status code

=item TEMPFAIL

Tempfail the SMTP command with a 4xx status code

=item REJECT

Reject the SMTP command with a 5xx status code

=item DISCARD

Accept the SMTP command, but discard the message rather than delivering it

=item ACCEPT_AND_NO_MORE_FILTERING

Accept the SMTP command, and do no further filtering of the message.

=back

=item code

A 3-digit SMTP reply code.  If not supplied, an appropriate code is picked
based on the value of C<status>.

=item dsn

A 3-numbered SMTP DSN of the form "X.Y.Z".  If not supplied, an appropriate
DSN is picked based on the value of C<status>.

=item message

A text message to include in the SMTP reply.  If not supplied, an appropriate
message is picked based on the value of C<status>

=item delay

A delay in seconds; if non-zero, C<mailmunge> will pause for this many
seconds before replying to the MTA.  This parameter should be used with
caution; if used at all, the delay should be at most a few seconds.

=back

=head2 Mailmunge::Response->CONTINUE(...)

Equivalent to C<Mailmunge::Response-E<gt>new(status =E<gt> 'CONTINUE', ...)>

=head2 Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING(...)

Equivalent to C<Mailmunge::Response-E<gt>new(status =E<gt> 'ACCEPT_AND_NO_MORE_FILTERING', ...)>

=head2 Mailmunge::Response->DISCARD(...)

Equivalent to C<Mailmunge::Response-E<gt>new(status =E<gt> 'DISCARD', ...)>

=head2 Mailmunge::Response->TEMPFAIL(...)

Equivalent to C<Mailmunge::Response-E<gt>new(status =E<gt> 'TEMPFAIL', ...)>

=head2 Mailmunge::Response->REJECT(...)

Equivalent to C<Mailmunge::Response-E<gt>new(status =E<gt> 'REJECT', ...)>

=head1 INSTANCE METHODS

=head2 code([$val])

Returns the C<code> value.  If an argument is supplied, the C<code>
is set to that value.

=head2 dsn([$val])

Returns the C<dsn> value.  If an argument is supplied, the C<dsn>
is set to that value.

=head2 delay([$val])

Returns the C<delay> value.  If an argument is supplied, the C<delay>
is set to that value.

=head2 message([$val])

Returns the C<message> value.  If an argument is supplied, the C<message>
is set to that value.

=head2 status([$val])

Returns the C<status> value.  If an argument is supplied, the C<status>
is set to that value.  If you supply an invalid status, then this
method croaks.

=head2 fix_code_dsn()

Fix up the C<code> and C<dsn> members so they make sense for the given
C<status>.  For example, if C<status> is TEMPFAIL, then C<code>
must be 4xx and C<dsn> must be 4.m.n.

=head2 is_tempfail()

Returns true if C<status> is TEMPFAIL; false otherwise.

=head2 is_discard()

Returns true if C<status> is DISCARD; false otherwise.

=head2 is_reject()

Returns true if C<status> is REJECT; false otherwise.

=head2 is_success()

Returns true if C<status> is CONTINUE or ACCEPT_AND_NO_MORE_FILTERING;
false otherwise.

=head2 is_success_or_discard()

Returns true if C<status> is CONTINUE, DISCARD or
ACCEPT_AND_NO_MORE_FILTERING; false otherwise.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.

=head1 SEE ALSO

L<Mailmunge::Filter>, L<Mailmunge::Context>, L<mailmunge>, L<mailmunge-multiplexor>
