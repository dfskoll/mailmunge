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

        # If we got back just a Mailmunge::Response, wrap it
        if (ref($ans) eq 'Mailmunge::Response') {
                return { response => $ans };
        }
        return $ans;
}

sub _rspamd_check_aux
{
        my ($self, $ctx, $sock) = @_;

        my $in;
        if (!open($in, '<', $self->filter->inputmsg)) {
                return Mailmunge::Response->TEMPFAIL(message => 'Unable to open message file');
        }

        my $headers = $self->_build_rspamd_request_headers($ctx);

        # Send the request
        $sock->print($headers);
        $sock->print("\r\n");
        my $buf;
        while(read($in, $buf, 4096)) {
                $sock->print($buf);
        }
        close($in);

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
        if ($results->{action} eq 'no action' || $results->{action} eq 'add header' || $results->{action} eq 'rewrite subject') {
                $resp = Mailmunge::Response->CONTINUE();
        } elsif ($results->{action} eq 'greylist'|| $results->{action} eq 'soft reject') {
                $resp = Mailmunge::Response->TEMPFAIL(message => 'Please try again later');
        } elsif ($results->{action} eq 'reject') {
                $resp = Mailmunge::Response->REJECT(message => 'Message rejected due to unacceptable content');
        }
        return { response => $resp, results => $results };
}

sub _build_spamd_request_headers
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

=head1 CLASS METHODS

=head2 Mailmunge::Test::SpamAssassin->new($filter)

Constructs a new Mailmunge::Test::SpamAssassin object and stores a copy
of $filter in it.

=head1 INSTANCE METHODS

=head2 rspamd_check($ctx, $host, $port)

Runs a SpamAssassin check against the current message.  C<$local_tests_only>
is passed as the C<local_tests_only> option to the C<Mail::SpamAssassin> constructor.
It is optional; if not supplied, it defaults to false.

C<$config> is the path to the SpamAssassin C<userprefs_fileanem>.  If not
supplied, Mailmunge uses the first file found out of:

=over 4

CONFDIR/sa-mailmunge.cf

CONFDIR/spamassassin/sa-mailmunge.cf

CONFDIR/spamassassin/local.cf

CONFDIR/spamassassin.cf

/etc/mail/sa-mailmunge.cf

/etc/mail/spamassassin/sa-mailmunge.cf

/etc/mail/spamassassin/local.cf

/etc/mail/spamassassin.cf

=back

where CONFDIR is the value of C<Mailmunge::Constants-E<gt>get('Path:CONFDIR')>.

C<spam_assassin_status> returns a C<Mail::SpamAssassin::PerMsgStatus>
object on success, or undef is something went wrong.  Note that when
you have finished using the returned status object, you should call
its C<finish()> method to free up resources.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.
