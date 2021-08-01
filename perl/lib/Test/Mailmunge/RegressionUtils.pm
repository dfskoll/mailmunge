use strict;
use warnings;

# These functions are all global functions in package main!

use JSON::Any;
use IO::Socket::INET;
use File::Basename;
use MIME::Parser;

# Get a message as a MIME::Entity
sub slurp_as_mime_entity
{
        my ($file) = @_;
        my $parser = MIME::Parser->new();
        $parser->extract_nested_messages(1);
        $parser->extract_uuencode(1);
        $parser->output_to_core(1);
        $parser->tmp_to_core(1);

        return $parser->parse_open($file);
}


# Get the BODY of a message after the headers
sub slurp_body_only
{
        my ($file) = @_;

        my $fh;
        if (!open($fh, '<', $file)) {
                return '';
        }
        while(<$fh>) {
                last if $_ eq "\n";
        }
        my $ans;
        {
                local $/;
                $ans = <$fh>;
        }
        $fh->close();
        return $ans;
}


sub server_running_postfix
{
        if (-d '/etc/postfix') {
                return 1;
        }
        return 0;
}

sub get_smtp_server_ip
{
        my $json = `ip --json addr`;
        my $array;
        eval {
                $array = JSON::Any->jsonToObj($json);
        };
        if (!$array) {
                return undef;
        }

        foreach my $addr (@$array) {
                next unless (($addr->{operstate} || '') eq 'UP');
                foreach my $info (@{$addr->{addr_info}}) {
                        next unless $info->{local};
                        # Don't want loopback
                        next if ($info->{local} =~ /^127\./);
                        return $info->{local};
                }
        }
        return undef;
}

sub smtp_send
{
        my ($ip, $helo, $sender, $recips, $msg) = @_;
        my $sock = IO::Socket::INET->new(PeerAddr => $ip,
                                         PeerPort => 25,
                                         Proto => 'tcp',
                                         Timeout => 5);
        if (!$sock) {
                return {stage => 'connect', code => 421, dsn => '4.2.1', txt => 'Could not create socket'};
        }

        # Unlink the maildrop file before sending
        my $maildrop_file = 'maildrop.msg';
        if ($msg =~ /^X-Mailmunge-Drop: \s*(.*)$/m) {
                $maildrop_file = $1;
                $maildrop_file =~ s[/\.\./][/];  # Remove .. in path
                $maildrop_file =~ s[/+][/];      # Remove multiple /
                $maildrop_file =~ s[^/][];       # Remove leading / if present
                $maildrop_file = basename($maildrop_file);
        }
        if ($maildrop_file && $maildrop_file !~ /%DEST%/) {
                unlink(maildrop_msg_path($maildrop_file));
        }

        my $err = _interpret_smtp_reply('connect', $sock);
        return $err if $err;

        $err = _do_smtp_command("EHLO $helo", 'helo', $sock);
        return $err if $err;

        $err = _do_smtp_command("MAIL From:<$sender>", 'mail', $sock);
        return $err if $err;

        foreach my $r (@$recips) {
                $err = _do_smtp_command("RCPT To:<$r>", 'rcpt', $sock);
                return $err if $err;
        }

        $err = _do_smtp_command('DATA', 'data', $sock);
        return $err if $err;

        $err = _smtp_data($msg, 'datasend', $sock);
        return $err if $err;

        $err = _do_smtp_command('QUIT', 'quit', $sock);
        return $err if $err;
        $sock->close();
        return {stage => 'quit', code => 200, dsn => '2.0.0', txt => 'OK'};
}

sub _smtp_data
{
        my ($msg, $stage, $sock) = @_;
        foreach my $line (split(/\n/, $msg)) {
                $line = ".$line" if $line eq '.';
                $sock->print("$line\r\n");
                print STDERR "SEND: $line\n" if $ENV{'MM_TEST_ECHO_SMTP_SESSION'};
        }
        $sock->printflush(".\r\n");
        print STDERR "SEND: .\n" if $ENV{'MM_TEST_ECHO_SMTP_SESSION'};
        return _interpret_smtp_reply($stage, $sock);
}

sub _interpret_smtp_reply
{
        my($stage, $sock) = @_;
        my ($code, $dsn, $txt);
        while(1) {
                my $line = $sock->getline();
                if (!$line) {
                        $sock->close();
                        return {stage => $stage, code => 421, dsn => '4.2.1', txt => 'No response from SMTP server'};
                }
                $line =~ s/\s+$//;
                print STDERR "RECV: $line\n" if $ENV{'MM_TEST_ECHO_SMTP_SESSION'};
                if ($line =~ /^(\d{3})-/) {
                        next;
                }
                if ($line =~ /^(\d{3}) (\d+\.\d+\.\d+) (.*)/) {
                        $code = $1;
                        $dsn = $2;
                        $txt = $3;
                } elsif ($line =~ /^(\d{3}) (.*)/) {
                        $code = $1;
                        $dsn = '';
                        $txt = $3;
                } else {
                        $sock->close();
                        return {stage => $stage, code => 421, dsn => '4.2.1', txt => "Unknown response from SMTP server: $line"};
                }

                if ($code >= 200 && $code < 400) {
                        # Everything's good; return undef
                        return undef;
                }
                $sock->printflush("QUIT\r\n");
                $sock->close();
                return { stage => $stage, code => $code, dsn => $dsn, txt => $txt };
        }
}

sub _do_smtp_command
{
        my ($cmd, $stage, $sock) = @_;

        $sock->printflush("$cmd\r\n");
        print STDERR "SEND: $cmd\n" if $ENV{'MM_TEST_ECHO_SMTP_SESSION'};
        return _interpret_smtp_reply($stage, $sock);
}

sub maildrop_msg_dir
{
        return '/tmp/mailmunge-drop';
}

sub clean_maildrop_dir
{
        my $dir = maildrop_msg_dir();
        system("rm -rf $dir/*");
}

sub maildrop_msg_path
{
        my ($file) = @_;
        $file = 'maildrop.msg' unless defined($file);
        return maildrop_msg_dir() . "/$file";
}

sub quarantine_dir
{
        return '/var/spool/mm-quarantine';
}

sub clean_quarantine_dir
{
        my $dir = quarantine_dir();
        system("rm -rf $dir/[0-9]*");
}

sub first_quarantined_msg
{
        my $dir = quarantine_dir();
        my $out = `find $dir -name ENTIRE_MESSAGE | head -n 1`;
        return undef unless $out;
        chomp($out);
        return undef if ($out eq '');
        return dirname($out);
}

sub make_msg
{
        my ($subject, $source_msg, $output_file) = @_;
        $source_msg = 'generic-msg' unless $source_msg;
        my $msg = `cat t/msgs/$source_msg`;
        my $ans = $msg;
        $ans =~ s/__SUBJECT__/$subject/;
        if (defined($output_file)) {
                $ans =~ s/: maildrop\.msg/: $output_file/;
        }
        return $ans;
}

sub wait_for_files
{
        for (my $i=0; $i<400; $i++) {
                # Flush the MTA queues every 50th time through the loop
                flush_mta_queues() if (!($i % 50));
                my $all_ok = 1;
                foreach my $file (@_) {
                        $all_ok = 0 unless -r $file;
                }
                return 1 if $all_ok;
                select(undef, undef, undef, 0.01);
        }
        return 0;
}

sub flush_mta_queues
{
        if (!server_running_postfix()) {
                system('/usr/sbin/sendmail -v -q -Ac < /dev/null > /dev/null 2>&1');
                system('/usr/sbin/sendmail -v -q < /dev/null > /dev/null 2>&1');
        } else {
                system('/usr/sbin/postqueue -v -f < /dev/null > /dev/null 2>&1');
        }
}

sub clean_mta_queues
{
        if (!server_running_postfix()) {
                # Sendmail: Brute force
                system("rm -f /var/spool/mqueue/*");
                return;
        }

        # Postfix: More elegant
        if (!open(IN, 'postqueue -j|')) {
                return;
        }
        while(<IN>) {
                my $item;
                eval {
                        $item = JSON::Any->jsonToObj($_);
                };
                next unless $item;
                if (ref($item) eq 'HASH') {
                        system('postsuper -d '. $item->{queue_id}. ' </dev/null >/dev/null 2>&1');
                }
        }
        close(IN);

}

sub _get_sendmail_hold_queue
{
        my @out;
        # Wait up to 2 seconds for sendmail to quarantine something
        my $now = time();
        while (time() - $now <= 2) {
                @out = glob('/var/spool/mqueue/h*');
                last if scalar(@out);
                select(undef, undef, undef, 0.1);
        }
        return \@out;
}

sub get_mta_hold_queue
{
        if (!server_running_postfix()) {
                return _get_sendmail_hold_queue();
        }

        my $out = [];
        # Wait up to 2 seconds for Postfix to quarantine something
        my $now = time();
        while (time() - $now <= 2) {
                my $stuff = `postqueue -j | fgrep hold 2>/dev/null`;
                last if $stuff =~ /hold/;
                select(undef, undef, undef, 0.1);
        }

        if (!open(IN, 'postqueue -j|')) {
                return $out;
        }
        while(<IN>) {
                my $item;
                eval {
                        $item = JSON::Any->jsonToObj($_);
                };
                next unless $item;
                if (ref($item) eq 'HASH') {
                        if ($item->{queue_name} eq 'hold') {
                                push(@$out, $item);
                        }
                }
        }
        close(IN);

        return $out;
}

1;

__END__

=head1 NAME

Test::Mailmunge::RegressionUtils - utility functions for Mailmunge regression tests

=head1 ABSTRACT

This class defines a number of functions in the I<main> package that are
useful for regression tests.

=head1 GIANT WARNING

The mailmunge regression-tests assume they are running in an environment
similar to the docker images built by the C<build-docker-container>
supplied in the mailmunge source code.  I<THEY ARE UNLIKELY TO
WORK IN ANY OTHER ENVIRONMENT>.

=head1 FUNCTIONS

=head2 slurp_body_only ($file)

C<$file> is assumed to be an RFC5322 mail message.  Return only
the I<body> of the message after skipping the header lines.

=head2 server_running_postfix()

Returns true if it looks like the regression-test server is running
Postfix; false otherwise.  We assume the server is running Sendmail
if it's not running Postfix.

=head2 get_smtp_server_ip()

Returns the regression-test server's IP address if it could
be determined; undef if not.  This will not be the loopback
address, but the IP address of a non-loopback interface.

=head2 smtp_send($ip, $helo, $sender, $recips, $msg)

Runs an SMTP session.  Connects to C<$ip> and HELOs as C<$helo>.
Use C<$sender> as the envelope sender.  Uses each recipient
in C<@$recips> in a RCPT To: command.  (C<$recips> must be an arrayref.)
And transmits C<$msg> as the message body; C<$msg> must be a string
representing an RFC5322 mail message.

Returns a hash containing:

=over 4

=item stage

The stage at which the SMTP session ended.  One of "connect",
"helo", "mail", "rcpt", "data", "datasend", or "quit".

=item code

The three-digit SMTP code returned by the SMTP server
for the final command sent.

=item dsn

The three-number "a.b.c" DSN returned by the SMTP
server for the final comand sent.

=item txt

The reply text returned by the SMTP server for the
final command sent.

=back


=head2 maildrop_msg_dir()

Returns the directory in which regression-test messages are dropped.

=head2 clean_maildrop_dir()

Deletes all files in C<maildrop_msg_dir()>

=head2 maildrop_msg_path([$file])

Returns the full path to the maildrop file.  If C<$file>
is not supplied, defaults to 'maildrop.msg'

=head2 quarantine_dir()

Returns the quarantine directory '/var/spool/mm-quarantine'

=head2 clean_quarantine_dir()

Deletes all files from the quarantine directory.

=head2 first_quarantined_msg()

Returns the first directory under
C<quarantine_dir()> that has a quarantined message.  Returns
undef if no quarantined messages are found.

=head2 make_msg($subject, $source_msg, $output_file)

Returns a string containing an RFC5322 message taken
from the file C<t/msgs/$source_msg>.  The string
C<__SUBJECT__> in that file is replaced with C<$subject>.
If C<$output_file> is provided, then the string
C<: maildrop.msg> in the source message is replaced
with C<: $output_file>.  This directs the regression-test
maildrop process to drop the message in
C<maildrop_msg_dir() . '/' . $output_file>

=head2 wait_for_files($file1 [, $file2 ...])

Waits up to (about) four seconds for all files named
in the argument list to exist.  Returns 1 if all
of the files exist, or 0 if the function timed
out before all files appeared.

=head2 flush_mta_queues()

Flushes the MTA queues using the appropriate commands depending on
whether the MTA is Sendmail or Postfix.  You need to run the
regression tests as root for this to work.

=head2 clean_mta_queues()

Clears out the MTA queues using the appropriate commands depending on
whether the MTA is Sendmail or Postfix.  Again, only works
if you're running as root.

=head2 get_mta_hold_queue()

Returns an arrayref of queue-IDs in the MTA's "hold" queue.  The
contents of the arrayref are unspecified, but the number of items is
the number of messages in the "hold" queue of the MTA.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.

