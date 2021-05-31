use strict;
use warnings;

package Test::Mailmunge::SMTPServer;

use IO::Socket::INET;
use POSIX ":sys_wait_h";

sub new
{
        my $class = shift;
        my $self = bless({ @_ }, $class);
        $self->_start_server();
        return $self;
}

sub _start_server
{
        my ($self) = @_;
        # Try up to 10 ports
        my $sock;
        for (my $i=9000; $i < 9010; $i++) {
                $sock = IO::Socket::INET->new(Listen => 5,
                                              LocalPort => $i,
                                              Proto => 'tcp',
                                              ReusePort => 1,
                                              ReuseAddr => 1);
                if ($sock) {
                        $self->{sock} = $sock;
                        $self->{port} = $i;
                        last;
                }
        }
        if (!$sock) {
                die("Could not create listening socket");
        }
        my $kid = fork();
        die("fork() failed") unless defined($kid);
        if ($kid) {
                # In the parent
                $self->{pid} = $kid;
                $sock->close();
                return;
        }

        # In the child
        $self->{pid} = $$;
        $self->_mainloop();
}

sub _sigchild
{
        my ($self) = @_;
        my $kid;
        do {
                $kid = waitpid(-1, WNOHANG);
                delete $self->{kids}->{$kid} if ($kid > 0);
        } while $kid > 0;
}

sub _sigterm
{
        my ($self) = @_;
        # In case sigterm is called in grandchild, do nothing
        return unless $self->{pid} == $$;

        foreach my $kid (keys(%{$self->{kids}})) {
                kill 'TERM', $kid;
        }
        exit(0);
}

sub _mainloop () {
        my ($self) = @_;
        $SIG{CHLD} = sub { $self->_sigchild(); };
        $SIG{TERM} = sub { $self->_sigterm(); };
        while(1) {
                my $sock = $self->{sock}->accept();
                if (!$sock) {
                        next if ($!{EINTR});
                        die("accept failed: $!");
                }
                $self->_smtp_server($sock);
        }
}

sub _getline
{
        my ($self, $sock) = @_;
        my $line = $sock->getline();
        if (!defined($line)) {
                exit(0);
        }
        $line =~ s/\s+$//;
        return $line;
}

sub _smtp_server
{
        my ($self, $sock) = @_;
        my $kid = fork();
        die("fork() failed: $!") unless defined($kid);

        if ($kid) {
                $self->{kids}->{$kid} = 1;
                return;
        }

        delete $SIG{'TERM'};

        # Reset $self->{sock} to the new socket
        $self->{sock} = $sock;
        # In the child
        if ($self->{connect}) {
                $self->{connect}->();
        } else {
                $sock->printflush("220 localhost.example.com ESMTP\r\n");
        }
        while(1) {
                my $line = $self->_getline($sock);

                if ($line =~ /^EHLO/i) {
                        $self->_ehlo($line);
                } elsif ($line =~ /^HELO/i) {
                        $self->_helo($line);
                } elsif ($line =~ /^MAIL FROM:/i) {
                        $self->_mail($line);
                } elsif ($line =~ /^RCPT TO:/i) {
                        $self->_rcpt($line);
                } elsif ($line =~ /^DATA/i) {
                        $self->_data($line);
                } elsif ($line =~ /^RSET/i) {
                        $sock->printflush("200 2.0.0 Reset\r\n");
                } elsif ($line =~ /^QUIT/i) {
                        $sock->printflush("221 2.0.0 Bye\r\n");
                        $sock->close();
                        delete $self->{sock};
                        delete $self->{pid};
                        exit(0);
                } else {
                        $sock->printflush("502 5.5.2 Error: $line: command not recognized\r\n");
                }
        }
}

sub _ehlo
{
        my ($self, $line) = @_;
        if ($self->{ehlo}) {
                my $resp = $self->{ehlo}->($line);
                $self->{sock}->printflush("$resp\r\n");
                return;
        }
        $self->{sock}->printflush("250-localhost.example.com\r\n250-SIZE 100000\r\n250 8BITMIME\r\n");
        return;
}
sub _helo
{
        my ($self, $line) = @_;
        if ($self->{helo}) {
                my $resp = $self->{helo}->($line);
                $self->{sock}->printflush("$resp\r\n");
                return;
        }
        $self->{sock}->printflush("250 localhost.example.com\r\n");
        return;
}

sub _mail
{
        my ($self, $line) = @_;
        if ($self->{mail}) {
                my $resp = $self->{mail}->($line);
                $self->{sock}->printflush("$resp\r\n");
                return;
        }
        $self->{sock}->printflush("250 2.1.0 Ok\r\n");
        return;
}


sub _rcpt
{
        my ($self, $line) = @_;
        if ($self->{rcpt}) {
                my $resp = $self->{rcpt}->($line);
                $self->{sock}->printflush("$resp\r\n");
                return;
        }
        $self->{sock}->printflush("250 2.1.0 Ok\r\n");
        return;
}

sub _data
{
        my ($self, $line) = @_;
        if ($self->{data}) {
                return $self->{data}->($self->{sock}, $line);
        }
        $self->{sock}->printflush("354 End data with <CR><LF>.<CR><LF>\r\n");
        while (my $line = $self->_getline($self->{sock})) {
                last if ($line eq '.');
        }
        $self->{sock}->printflush("200 2.1.5 Message accepted\r\n");
}

sub stop_server
{
        my ($self) = @_;
        if ($self->{sock}) {
                $self->{sock}->close();
                delete $self->{sock};
        }
        if ($self->{pid}) {
                kill 'TERM', $self->{pid};
                delete $self->{pid};
        }
}

sub DESTROY
{
        my ($self) = @_;
        $self->stop_server();
}

1;

__END__

=head1 NAME

Test::Mailmunge::SMTPServer - run a fake SMTP server for unit-test purposes

=head1 ABSTRACT

Test::Mailmunge::SMTPServer runs a fake SMTP server.  It is used (for example)
to test Mailmunge::Test::SMTPForward

=head1 SYNOPSIS

    use Test::Mailmunge::SMTPServer;
    my $server = Test::Mailmunge::SMTPServer->new();
    my $port = $server->{port};
    # Now interact with server on 127.0.0.1 at port $port

    # DON'T FORGET to stop the server when done!
    $server->stop_server();

=head1 CONSTRUCTOR

=head2 Test::Mailmunge::SMTPServer->new($callback1 => \&func1, ...)

Constructs and starts a new test SMTP server.  Supply callbacks
to tell the server how to respond to SMTP client commands.
The possible callbacks are:

=over 4

=item connect => \&coderef

If supplied, then C<coderef> is called with C<$self> as the
only argument when an SMTP client connects.

It should print a reply to the socket $self->{sock}.  If no C<connect>
callback is supplied, then the default response printed to the socket
is:

    "220 localhost.example.com ESMTP\r\n"

=item ehlo => \&coderef

If supplied, then when an SMTP client issues the EHLO command,
C<coderef> is called with C<$self> and C<$line> as arguments, where
C<$line> is the complete line read from the SMTP client.

It should print a reply to the socket $self->{sock}.  If no C<ehlo>
callback is supplied, then the default response printed to the socket
is:

    "250-localhost.example.com\r\n250-SIZE 100000\r\n250 8BITMIME\r\n"

=item helo => \&coderef

Similar to C<ehlo>, but called if the client issues the HELO command.
The default response is:

    "250 localhost.example.com\r\n"

=item mail => \&coderef

Similar to C<ehlo>, but called if the client issues the MAIL From: command.
The default response is:

    "250 2.1.0 Ok\r\n"

=item rcpt => \&coderef

Similar to C<ehlo>, but called if the client issues the RCPT To: command.
The default response is:

    "250 2.1.0 Ok\r\n"

=item data => \&coderef

Similar to C<ehlo>, but called if the client issues the DATA command.
The default response is:

    "354 End data with <CR><LF>.<CR><LF>\r\n"

=back

=head1 INSTANCE METHOD

=head2 $server->stop_server()

Stops the SMTP server.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.


