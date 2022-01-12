use strict;
use warnings;
package Mailmunge::Test::Rspamd;
use base qw(Mailmunge::Test);

use Mailmunge::Constants;
use IO::Socket::INET;
use JSON::Any;

sub rspamd_check
{
        my ($self, $ctx, $host, $port, $timeout) = @_;
        $timeout = 300 unless defined $timeout;

        my $sock = IO::Socket::INET->new(PeerHost => $host,
                                         PeerPort => $port,
                                         Proto    => 'tcp',
                                         Timeout  => 5);
        if (!$sock) {
                return { response => Mailmunge::Response->TEMPFAIL(message => 'Unable to connect to rspamd') };
        }

        local $SIG{ALRM} = sub { die("Timeout"); };
        my $ans;
        eval {
                alarm($timeout);
                $ans = $self->_rspamd_check_aux($ctx, $sock);
        };
        alarm(0);
        $sock->close();
        if ($@ =~ /Timeout/) {
                return { response => Mailmunge::Response->TEMPFAIL(message => 'Calling rspamd timed out') };
        }

        if (!$ans) {
                return { response => Mailmunge::Response->TEMPFAIL(message => 'Calling rspamd failed') };
        }

        # If we got back just a Mailmunge::Response, wrap it
        if (ref($ans) eq 'Mailmunge::Response') {
                return { response => $ans };
        }
        return $ans;
}

sub _rspamd_check_aux
{
        my ($self, $ctx, $sock) = @_;

        if (!open(IN, '<', $self->inputmsg())) {
                return Mailmunge::Response->TEMPFAIL(message => 'Unable to open message file');
        }

        my $headers = $self->_build_rspamd_request_headers($ctx);

        # Send the request
        $sock->print($headers);
        $sock->print("\r\n");
        my $buf;
        while(read(IN, $buf, 4096)) {
                $sock->print($buf);
        }
        close($in);
        $sock->flush();

        # Read the results
        my $results = $self->_read_rspamd_results($sock);
        if (!$results) {
                return Mailmunge::Response->TEMPFAIL(message => 'Failed to read results from rspamd');
        }

        if (!ref($results)) {
                # If we get back a scalar, it's an error message
                return Mailmunge::Response->TEMPFAIL(message => $results);
        }
        if ($results->{is_skipped}) {
                return { response => Mailmunge::Response->CONTINUE(),
                         results  => $results };
        }
        if (!$results->{action}) {
                return { response => Mailmunge::Response->TEMPFAIL(message => 'rspamd results did not contain an "action" key'),
                         results => $results };
        }

        # Build a response based on "action"
        my $resp;
        # Note that if rspamd recommends a policy, we leave it
        # to the caller to decide to implement the policy
        if ($results->{action} eq 'greylist'|| $results->{action} eq 'soft reject') {
                $resp = Mailmunge::Response->TEMPFAIL(message => 'Please try again later');
        } elsif ($results->{action} eq 'reject') {
                $resp = Mailmunge::Response->REJECT(message => 'Message rejected due to unacceptable content');
        } else {
                $resp = Mailmunge::Response->CONTINUE();
        }
        return { response => $resp, results => $results };
}

sub _build_rspamd_request_headers
{
        my ($self, $ctx) = @_;

        my $size = -s $self->filter->inputmsg;

        my $hdrs =
            "POST /checkv2 HTTP/1.0\r\n" .
            "Content-Length: $size\r\n"  .
            "From: "     . $ctx->sender     . "\r\n" .
            "IP: "       . $ctx->hostip     . "\r\n" .
            "Helo: "     . $ctx->helo       . "\r\n" .
            "From: "     . $ctx->sender     . "\r\n" .
            "Queue-Id: " . $ctx->qid        . "\r\n";
        foreach my $r (@{$ctx->recipients}) {
                $hdrs .= "Rcpt: " . $r . "\r\n";
        }
        return $hdrs;
}

sub _read_rspamd_results
{
        my ($self, $sock) = @_;

        my $resp = $sock->getline();
        $resp =~ s/\s+$//;

        if ($resp !~ m|^HTTP/\d+\.\d+ (\d+) (.*)|) {
                return "Could not interpret rspamd response: $resp";
        }
        if ($1 ne '200') {
                return "Unsuccessful response from rspamd: $resp";
        }

        # Read the headers
        while($resp = $sock->getline()) {
                $resp =~ s/\s+$//;
                last if $resp eq '';
                if ($resp =~ /^Content-Type:\s*(.*)/i) {
                        if (lc($1) ne 'application/json') {
                                return "Expecting application/json response from rspamd; found $1";
                        }
                }
        }

        my $results;

        # Read the JSON blob
        local $/;
        my $json = <$sock>;
        eval {
                $results = JSON::Any->jsonToObj($json);
        };
        if (!$results) {
                return "Unable to parse rspamd response as JSON";
        }
        if (ref($results) ne 'HASH') {
                return "Expecting a HASH response from rspamd, found " . (ref($results) || "'$results'");
        }
        return $results;
}

1;

__END__

=head1 NAME

Mailmunge::Test::Rspamd - run a message through rspamd

=head1 ABSTRACT

This class connects to an L<rspamd|https://www.rspamd.com/> daemon and
passes the input message to rspamd for evaluation.

=head1 SYNOPSIS

    package MyFilter;
    use Mailmunge::Test::Rspamd;

    sub filter_begin {
        my ($self, $ctx) = @_;
        my $test = Mailmunge::Test::Rspamd->new($self);
        my $ans = $test->rspamd_check($ctx, '127.0.0.1', 11333);
        my $resp = $ans->{response};
        if (!$ans->{results}) {
            # Failure of some kind - timeout, rspamd not running, etc.
            # Specific error message will be in $ans->{response}->message
            return $self->action_tempfail($ctx, $resp->message);
        }

        # We have rspamd results; you can inspect $ans->{results}
        # to decide what action to take, or use the code below to take
        # action based on $ans->{respones}; $ans->{response} is a
        # Mailmunge::Response object with a suggested response

        if ($self->action_from_response($ctx, $resp)) {
            # Rspamd suggested an action, which we took
            return;
        }

        # Must be: $resp->is_success so continue with rest of filter
    }

=head1 CLASS METHODS

=head2 Mailmunge::Test::Rspamd->new($filter)

Constructs a new Mailmunge::Test::Rspamd object and stores a copy
of $filter in it.

=head1 INSTANCE METHODS

=head2 rspamd_check($ctx, $host, $port [, $timeout])

Connects to the rspamd daemon on the given $host and $port and asks it
to evaluate the current message.  $timeout is an overall timeout in
seconds for rspamd to reply; if not supplied, it defaults to 300
seconds.

The return value from C<rspamd_check> is a hash with the following
elements:

=over

=item response

A Mailmunge::Response object with the suggested response to the message.
If something went wrong with rspamd, then the C<response> element will
be the only element in the hash.  Its C<status> will be set to
C<TEMPFAIL> and its C<message> will contain an error message.

=item results

If rspamd successfully scanned the message, the C<results> element
will be a hash containing the rspamd response.  This data structure
is described in detail at L<https://www.rspamd.com/doc/architecture/protocol.html#rspamd-http-reply>.  It is up to the caller of C<rspamd_check>
to inspect the reply from rspamd and call appropriate functions such
as C<action_reject>, etc.

If rspamd did not successfully scan the message, then there will be
no C<results> element.

=back

=head1 SEE ALSO

rspamd at L<https://www.rspamd.com/>

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
