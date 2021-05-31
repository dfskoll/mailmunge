use strict;
use warnings;

package Mailmunge::Test::SMTPForward;
use base qw(Mailmunge::Test);

use Socket;
use IO::Socket;
use IO::Socket::SSL;

sub _get_smtp_extensions {
        my($self, $recip, $server, $sock, $exts) = @_;
        my($ext, $msg, $delim, $line, $code, $text, $retval, $dsn);
        my %exts;
        $delim='-';
        my $first = 1;
        while ( ($delim eq '-' ) && (defined ($line = $sock->getline())))  {
                # Chew up all trailing white space, including CR
                $line =~ s/\s+$//;
                $line =~ m/([245][0-9][0-9])([- ])([^ ]+) *(.*)/  or return Mailmunge::Response->TEMPFAIL(message => "$server said: $line");
                $code=$1;
                $delim=$2;
                $ext=$3;
                $text=$4;
                if ($first) {
                        $exts->{'hostname'} = $ext;
                        $first = 0;
                        next;
                }
                $exts->{$ext} = $text;
        }

        $code =~ m/2../ and return Mailmunge::Response->CONTINUE(code => $code, dsn => '2.5.0');
        $code =~ m/4../ and return Mailmunge::Response->TEMPFAIL(code => $code, dsn => '4.0.0');
        return Mailmunge::Response->REJECT(code => $code, dsn => '5.0.0');
}

sub _get_smtp_return_code
{
        my ($self, $ctx, $recip, $server, $sock) = @_;

        my $filter = $self->filter;

        my($line, $code, $text, $retval, $dsn);
        while (defined ($line = $sock->getline())) {
                $line =~ s/\s+$//;
                if ($line =~ /^\d\d\d$/ || $line =~ /^\d\d\d\s/) {
                        $line =~ /^(\d\d\d)\s*(.*)$/;
                        $code = $1;
                        $text = $2;
                        # Check for DSN
                        if ($text =~ /^(\d\.\d{1,3}\.\d{1,3})\s+(.*)$/) {
                                $dsn = $1;
                                $text = $2;
                        } else {
                                $dsn = "";
                        }
                        if ($code =~ /^[123]/) {
                                return Mailmunge::Response->CONTINUE(code => $code, message => $text, dsn => $dsn);
                        } elsif ($code =~ /^4/) {
                                $filter->log($ctx, 'debug', "check_against_smtp_server: $server: $recip: $code $dsn $text");
                                return Mailmunge::Response->TEMPFAIL(code => $code, message => $text, dsn => $dsn);
                        } elsif ($code =~ /^5/) {
                                $filter->log($ctx, 'debug', "check_against_smtp_server: $server: $recip: $code $dsn $text");
                                return Mailmunge::Response->REJECT(code => $code, message => $text, dsn => $dsn);
                        } else {
                                $filter->log($ctx, 'warning', "check_against_smtp_server: $server: $recip: Invalid SMTP reply code $code");
                                return Mailmunge::Response->TEMPFAIL(message => "Invalid SMTP reply code $code from server $server for $recip",
                                                              code => 451, dsn => '4.3.0');
                        }
                }
        }

        my $msg;
        if( defined $line ) {
                $msg = "_get_smtp_return_code: Invalid response [$line] from SMTP server";
                $filter->log($ctx, 'info', "check_against_smtp_server: $server: $recip: Invalid response [$line]");
        } else {
                $msg = "_get_smtp_return_code: Empty response from SMTP server";
                $filter->log($ctx, 'info', "check_against_smtp_server: $server: $recip: Empty response");
        }
        return Mailmunge::Response->TEMPFAIL(message => $msg, code => 451, dsn => '4.3.0');
}

sub _quit
{
        my ($self, $ctx, $recip, $server, $sock) = @_;
        $sock->printflush("QUIT\r\n");
        $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        $sock->close();
}

sub _starttls
{
        my ($self, $ctx, $recip, $server, $helo_host, $sock) = @_;
        my $resp;

        my $filter = $self->filter;

        $sock->printflush("STARTTLS\r\n");
        $resp = $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        return $resp unless $resp->is_success;

        if ($sock->connect_SSL) {
                $filter->log($ctx, 'debug', "check_against_smtp_server: $server: $recip: STARTTLS succeeded");
                $sock->printflush("EHLO $helo_host\r\n");
                return $resp;
        }
        $sock->stop_SSL;
        no warnings 'once';
        $filter->log($ctx, 'debug', "check_against_smtp_server: $server: $recip: offered STARTTLS, but failed with $IO::Socket::SSL:SSL_ERROR.  Falling back to plaintext");
        $sock->printflush('RSET');
        $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        $sock->printflush("EHLO $helo_host\r\n");
        return $resp;
}

# Some mail servers tempfail when they
# really should permfail.  Try to detect
# those with a big horrible regex...

my $convert_to_reject = qr/DNS A-record is empty$|DNS server failure$|Mailbox Full$|Mailbox size limit exceeded$|Message size exceeds fixed limit$|No such user.*-FAIL|Recipient address rejected: User unknown in local recipient table$|Recipient address rejected: User unknown in virtual mailbox table$|Recipient address rejected: unverified address: unknown user: ".*"$|Refused. The domain of your sender address has no mail exchanger|Relay access denied$|Sender address rejected: Domain not found$|User has exceeded his\/her disk space limit\.$/;


sub check_against_smtp_server
{
        my ($self, $ctx, $recip, $server, $port) = @_;

        my $filter = $self->filter;

        my ($resp, $sender);

        $port = 25 unless defined($port);
        $sender = $ctx->sender;
        $sender = "<$sender>" unless $sender =~ /^<.*>$/;
        $recip = "<$recip>" unless $recip =~ /^<.*>$/;

        my $helo_host = $ctx->connecting_name || '[' . $ctx->connecting_ip . ']';

        my $sock = IO::Socket::SSL->new(
                PeerAddr             => $server,
                SSL_startHandshake   => 0,
                SSL_verify_mode      => SSL_VERIFY_NONE,
                SSL_hostname         => $server,
                PeerPort             => $port,
                Proto                => 'tcp',
                Timeout              => 25);
        return Mailmunge::Response->TEMPFAIL(message => "Could not connect to SMTP server $server: $!") unless $sock;

        $resp = $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        if (!$resp->is_success) {
                $self->_quit($ctx, $recip, $server, $sock);
                return $resp;
        }

        # Check for smtp forwarding loop
        if ($server ne '127.0.0.1' && $server ne '::1') {
                my $host_expr = quotemeta($filter->get_host_name());
                if ($resp->message =~ /^$host_expr\b/) {
                        $self->_quit($ctx, $recip, $server, $sock);
                        return Mailmunge::Response->REJECT(message => "Verification server loop: Trying to verify $recip against myself",
                                                    code => 554, dsn => '5.4.6');
                }
        }

        if ($resp->message =~ /\bESMTP\b/) {
                $sock->printflush("EHLO $helo_host\r\n");
                my %exts;
                $resp = $self->_get_smtp_extensions($recip, $server, $sock, \%exts);
                if (!$resp->is_success) {
                        $sock->printflush("HELO $helo_host\r\n");
                } else {
                        if (exists($exts{'STARTTLS'})) {
                                $resp = $self->_starttls($ctx, $recip, $server, $helo_host, $sock);
                                if (!$resp->is_success) {
                                        $sock->printflush("RSET\r\n");
                                        $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
                                        $sock->printflush("EHLO $helo_host\r\n");
                                }
                        } else {
                                $sock->printflush("RSET\r\n");
                                $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
                                $sock->printflush("EHLO $helo_host\r\n");
                        }
                }
        } else {
                $sock->printflush("HELO $helo_host\r\n");
        }

        # At this point, we've either sent a fallback HELO, fallback EHLO,
        # or internal-to-starttls EHLO, so get the response
        $resp = $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        if (!$resp->is_success) {
                $self->_quit($ctx, $recip, $server, $sock);
                return $resp;
        }

        $sock->printflush("MAIL From:$sender\r\n");
        $resp = $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        if (!$resp->is_success) {
                $self->_quit($ctx, $recip, $server, $sock);
                return $resp;
        }

        $sock->printflush("RCPT To:$recip\r\n");
        $resp = $self->_get_smtp_return_code($ctx, $recip, $server, $sock);
        $self->_quit($ctx, $recip, $server, $sock);

        if ($resp->is_tempfail) {
                if ($resp->message =~ /$convert_to_reject/) {
                        $filter->log($ctx, 'info', "check_against_smtp_server: $server: $recip: Converting tempfail to reject: " . $resp->message);
                        $resp->status('REJECT');
                        $resp->fix_code_dsn();
                }
        }
        return $resp;
}

1;

__END__

=head1 NAME

Mailmunge::Test::SMTPForward - Peform an SMTP callback to see if another
SMTP server would accept a recipient.

=head1 ABSTRACT

This class performs a mini SMTP session on a back-end SMTP server
to see if that server would accept a recipient.  It uses
$ctx->connecting_name as the HELO argument and $ctx->sender as the
MAIL From: argument.

C<Mailmunge::Test::SMTPForward> is a subclass of C<Mailmunge::Test>.

=head1 SYNOPSIS

    package MyFilter;
    use Mailmunge::Test::SMTPForward;

    sub filter_recipient {
        my ($self, $ctx) = @_;
        my $forwarder = Mailmunge::Test::SMTPForward->new($self);
        my $resp = $forwarder->check_against_smtp_server($ctx,
                   $ctx->recipients->[0],
                   'backend.example.com');
        return $resp unless $resp->is_success();
        # ... rest of filter_recipient
    }

=head1 CLASS METHOD

=head2 Mailmunge::Test::SMTPForward->new($filter)

Constructs a new Mailmunge::Test::SMTPForward object and stores a copy
of $filter in it.

=head1 INSTANCE METHOD

=head2 check_against_smtp_server($ctx, $recipient, $server [, $port]);

Run a mini-SMTP session against C<$server> on port C<$port> (default is
port 25) to see if it would accept the recipient C<$recipient>.

The return value is a C<Mailmunge::Response> object whose value reflects
the response of the back-end SMTP server.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.
