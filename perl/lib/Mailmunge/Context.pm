use strict;
use warnings;

package Mailmunge::Context;
use base qw(Mailmunge::Base);

use Mailmunge::Constants;
use Sys::Syslog;

my @accessors = qw(
    bounced
    client_port
    connecting_ip
    connecting_name
    cwd
    discarded
    esmtp_args
    first_recip
    helo
    hostip
    hostname
    in_filter_wrapup
    mailmunge_id
    message_id
    message_quarantined
    mime_entity
    mta_is_postfix
    my_ip
    my_port
    qid
    rcpt_addr
    rcpt_host
    rcpt_mailer
    recipient_esmtp_args
    recipients
    sender
    subject
    subject_count
    suspicious_chars_in_body
    suspicious_chars_in_headers
    tempfailed
    was_resent
);

sub privdata
{
        my ($self, $key, $val) = @_;
        if (defined($val)) {
                $self->{privdata}->{$key} = $val;
        }
        return $self->{privdata}->{$key};
}

sub new_mime_entity
{
        my ($self, $val) = @_;
        if ($val) {
                # Ignore attempts to set new_mime_entity from
                # filter_wrapup.  Should really log, I guess.
                return undef if ($self->{in_filter_wrapup});
                $self->{new_mime_entity} = $val;
                $self->{mime_entity} = $val;
        }
        return $self->{new_mime_entity};
}

sub in_message_context
{
        my ($self, $set) = @_;
        if (defined($set)) {
                $self->{in_message_context} = $set;
                return $set;
        }

        if (!$self->{in_message_context}) {
                my @stuff = caller(0);
                my $method = $stuff[3];
                @stuff = caller(1);
                my $who = $stuff[3];
                $self->log('warning', "$method called outside of message context by $who");
        }
        return $self->{in_message_context};
}

sub message_rejected
{
        my ($self) = @_;
        return $self->bounced || $self->discarded || $self->tempfailed;
}

sub _incr_subject_count
{
        my ($self) = @_;
        $self->{subject_count}++;
}

sub _push_esmtp_arg
{
        my ($self, $arg) = @_;
        push(@{$self->{esmtp_args}}, $arg);
}

sub _push_recipient
{
        my ($self, $recip) = @_;
        push(@{$self->{recipients}}, $recip);
}

sub _set_recipient_mailer
{
        my ($self, $recip, $mailer_triple) = @_;
        $self->{recipient_mailer}->{$recip} = $mailer_triple;
}

sub get_recipient_mailer
{
        my ($self, $recip) = @_;
        return $self->{recipient_mailer}->{$recip};
}

sub _push_recipient_esmtp_args
{
        my ($self, $recip, $arg) = @_;
        push(@{$self->{recipient_esmtp_args}->{$recip}}, $arg);
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
        return $self;
}

sub _read_command_filehandle
{
        my ($self, $filter, $fh, $need_f) = @_;
        my $recent_recip;
        my $seen_f = 0;

        while(<$fh>) {
                chomp;
                my $rawcmd = $_;
                my $cmd = $filter->_percent_decode($rawcmd);
                my $arg = substr($cmd, 1);
                $cmd = substr($cmd, 0, 1);
                my $rawarg = substr($rawcmd, 1);

                # The simple ones can be done as one-liners
                if    ($cmd eq 'S') { $self->sender($arg); }
                elsif ($cmd eq 's') { $self->_push_esmtp_arg($arg); }
                elsif ($cmd eq 'F') { $seen_f = 1; last; }
                elsif ($cmd eq 'r') { $self->_push_recipient_esmtp_args($recent_recip, $arg) if ($recent_recip); }
                elsif ($cmd eq '!') { $self->suspicious_chars_in_headers(1); }
                elsif ($cmd eq '?') { $self->suspicious_chars_in_body(1); }
                elsif ($cmd eq 'I') { $self->hostip($arg); $self->connecting_ip($arg); }
                elsif ($cmd eq 'H') { $self->hostname($arg); $self->connecting_name($arg); }
                elsif ($cmd eq 'Q') { $self->qid($arg); }
                elsif ($cmd eq 'X') { $self->message_id($arg); }
                elsif ($cmd eq 'E') { $self->helo($arg); }
                elsif ($cmd eq 'i') { $self->mailmunge_id($arg); }

                # These ones need blocks, so don't squeeze
                # into one line
                elsif ($cmd eq '=') {
                        my ($macro, $value) = split(/\s+/, $rawarg);
                        $value = "" unless defined($value);
                        $macro = "" unless defined($macro);
                        if ($macro ne "") {
                                $macro = $filter->_percent_decode($macro);
                                $value = $filter->_percent_decode($value);
                                $self->sendmail_macro($macro, $value);
                        }
                } elsif ($cmd eq 'U') {
                        $self->_incr_subject_count();
                        if ($self->subject_count() == 1) {
                                $self->subject($arg);
                        } elsif ($self->subject_count() < 5) {
                                $filter->log($self, 'warning', "Message contains more than one Subject: header: " . $self->subject() . " --> $arg");
                        } elsif ($self->subject_count() == 5) {
                                $filter->log($self, 'warning', "Message contains at least five Subject: headers: " . $self->subject() . " --> $arg");
                        }
                } elsif ($cmd eq 'R') {
                        my ($recip, $rcpt_mailer, $rcpt_host, $rcpt_addr) = map { $filter->_percent_decode($_, '?') } (split(' ', $rawarg));
                        $self->_push_recipient($recip);
                        $self->_set_recipient_mailer($recip, [$rcpt_mailer, $rcpt_host, $rcpt_addr]);
                        $recent_recip = $recip;
                } else {
                        $filter->log($self, 'warning', "Unknown command $cmd from mailmunge");
                }
        }
        close($fh);
        if ($need_f && !$seen_f) {
                $filter->log($self, 'err', "COMMANDS file from mailmunge did not terminate with 'F' -- check disk space in spool directory");
                $filter->_signal_complete();
                $filter->reply_error("COMMANDS file from mailmunge did not terminate with 'F'");
                return undef;
        }
        return $self;
}

sub sendmail_macro
{
        my ($self, $macro, $val) = @_;

        $self->{sendmail_macros}->{$macro} = $val if defined($val);
        return $self->{sendmail_macros}->{$macro};
}


sub mta_macro
{
        my ($self, $macro, $val) = @_;
        return $self->sendmail_macro($macro, $val);
}

sub _time_str
{
        my ($self, $now) = @_;
        $now = time() unless defined($now);
        my ($sec, $min, $hour, $mday, $mon, $year, $junk) = localtime($now);
        return sprintf("%04d-%02d-%02d-%02d.%02d.%02d",
                       $year + 1900, $mon+1, $mday, $hour, $min, $sec);
}

sub _hour_str
{
        my ($self, $now) = @_;
        $now = time() unless defined($now);
        my ($sec, $min, $hour, $mday, $mon, $year, $junk) = localtime($now);
        return sprintf('%04d-%02d-%02d-%02d', $year+1900, $mon+1, $mday, $hour);
}

sub get_quarantine_dir
{
        my ($self) = @_;
        my $qdir = Mailmunge::Constants->get('Path:QUARANTINEDIR');
        return undef unless $qdir;

        my $hour_dir = sprintf("%s/%s", $qdir, $self->_hour_str());
        mkdir($hour_dir, 0750);
        return undef unless (-d $hour_dir);

        my $q_subdir;
        my $tm = $self->_time_str();
        my $count = 0;
        while ($count++ < 10000) {
                $q_subdir = sprintf("%s/qdir-%s-%04d",
                                    $hour_dir, $tm, $count);
                last if (mkdir($q_subdir, 0750));
        }
        return $q_subdir if (-d $q_subdir);
        return undef;
}

sub _write_quarantine_info
{
        my ($self, $qdir) = @_;
        if ($self->sender && open(OUT, ">$qdir/SENDER")) {
                print OUT $self->sender . "\n";
                close(OUT);
        }
        if ($self->qid && open(OUT, ">$qdir/MTA-QID")) {
                print OUT $self->qid . "\n";
                close(OUT);
        }
        if (scalar(@{$self->{recipients}}) && open(OUT, ">$qdir/RECIPIENTS")) {
                foreach my $r (@{$self->{recipients}}) {
                        print OUT "$r\n";
                }
                close(OUT);
        }
        $self->copy_or_link(Mailmunge::Filter->headers_file, "$qdir/HEADERS");
}

sub canonical_sender
{
        my ($self) = @_;
        return Mailmunge::Filter->canonical_email($self->sender);
}

sub canonical_recipients
{
        my ($self) = @_;
        my @recips = map { Mailmunge::Filter->canonical_email($_) } (@{$self->recipients});
        return \@recips;
}

sub log
{
        my ($self, $level, $msg) = @_;

        my $qid = $self->qid;
        if (defined($qid) && $qid ne 'NOQUEUE' && $qid ne '') {
                syslog($level, '%s', $qid . ': ' . $msg);
        } else {
                syslog($level, '%s', $msg);
        }
}

# Private function: Get a filenhandle for writing to the
# RESULTS file.  Dies if it cannot open RESULTS.
sub _results_fh
{
        my ($self) = @_;
        if (!$self->{results_fh}) {
                $self->{results_fh} = IO::File->new('>>RESULTS');
                if (!$self->{results_fh}) {
                        die("Could not open RESULTS file: $!");
                }
        }
        return $self->{results_fh};
}

# Private function: Close the RESULTS filehandle.
# Dies if close() returns an error.
sub _close_results_fh
{
        my ($self) = @_;
        if ($self->{results_fh}) {
                if (!$self->{results_fh}->close()) {
                        die("Could not close RESULTS file: $!");
                }
                delete $self->{results_fh};
        }
}

# Private function
# _write_result_line($cmd, @args)
# Writes the line to RESULTS, percent-escaping each member of @args.
sub _write_result_line
{
        my $self = shift;
        my $cmd  = shift;

        my $fh = $self->_results_fh();

        my $line = $cmd . join(' ', map { Mailmunge::Filter->_percent_encode($_) } (@_));
	# We have an 8kb limit on the length of lines in RESULTS, including
	# trailing newline and null used in the milter.  So, we limit $cmd +
	# $args to 8190 bytes.
	if( length $line > 8190 ) {
		$self->log( 'warning',  "Cannot write line over 8190 bytes long to RESULTS file; truncating.  Original line began with: " . substr $line, 0, 40);
		$line = substr $line, 0, 8190;
	}
        print $fh "$line\n" or die("Could not write RESULTS line: $!");
}

# Private function
# Writes the 'F' command to RESULTS and closes the RESULTS
# filehandle.
sub _signal_complete
{
        my ($self) = @_;
        $self->_write_result_line('F');
        $self->_close_results_fh();
}

# Private function
# Writes the 'C' command to RESULTS to tell the C code to replace
# the message body
sub _signal_changed
{
        my ($self) = @_;
        $self->_log_if_postfix('info', 'Message body replaced');
        $self->_write_result_line('C');
}

# Private function
# Log only if the MTA is Postfix.  Sendmail
# is much more verbose about logging Milter
# events than Postfix, so we do additional
# logging if the MTA is Postfix.
sub _log_if_postfix
{
        my ($self, $level, $msg) = @_;
        return unless $self->mta_is_postfix();
        $self->log($level, $msg);
}

=head2 action_from_response ($resp)

Given a L<Mailmunge::Response> object C<$resp>, take the appropriate action.
This function operates as follows:

=over

if C<$resp> is not defined, or is not a C<Mailmunge::Response> object, return 0.

If C<$resp-E<gt>is_tempfail>, call C<$self-E<gt>action_tempfail($resp-E<gt>message)> and return 1

If C<$resp-E<gt>is_reject>, call C<$self-E<gt>action_bounce($resp-E<gt>message)> and return 1

If C<$resp-E<gt>is_discard>, call C<$self-E<gt>action_discard()> and return 1

Otherwise, return 0.

=back

=cut
sub action_from_response
{
        my ($self, $resp) = @_;

        return 0 unless $resp && ref($resp);
        my $isa_response;
        eval { $isa_response = $resp->isa('Mailmunge::Response'); };
        return 0 unless $isa_response;

        if ($resp->is_tempfail) {
                $self->action_tempfail($resp->message);
                return 1;
        }

        if ($resp->is_reject) {
                $self->action_bounce($resp->message);
                return 1;
        }

        if ($resp->is_discard) {
                $self->action_discard();
                return 1;
        }

        # Didn't do anything
        return 0;
}

=head2 action_bounce($reply, $code, $dsn)

Ask the MTA to bounce the message.  $reply is the text of the bounce;
code is a 3-digit 5xy reply code, and $dsn is a three-numbered 5.x.y
DSN code.

Writes the 'B' line to RESULTS to tell the C code to bounce
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_bounce
{
        my ($self, $reply, $code, $dsn) = @_;
        return 0 unless $self->in_message_context();

        # Convert bounce to discard for resent mail
        if ($self->was_resent) {
                $self->log('info', 'Converting "bounce" to "discard" for resent mail');
                return $self->action_discard();
        }

        $self->bounced(1);
        $reply = "Forbidden for policy reasons" unless (defined($reply) and ($reply ne ""));
        $code = 554 unless (defined($code) and $code =~ /^5\d\d$/);
        $dsn = "5.7.1" unless (defined($dsn) and $dsn =~ /^5\.\d{1,3}\.\d{1,3}$/);

        $self->_write_result_line('B', $code, $dsn, $reply);
        return 1;
}

=head2 action_discard()

Ask the MTA to discard the message.

Writes the 'D' line to RESULTS to tell the C code to discard
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_discard
{
        my ($self) = @_;
        return 0 unless $self->in_message_context();
        $self->discarded(1);
        $self->_write_result_line('D', '');
        return 1;
}

=head2 action_tempfail($reply, $code, $dsn)

Ask the MTA to tempfail the message.
$reply is the text of the tempfail response; code is a 3-digit 4xy
reply code, and $dsn is a three-numbered 4.x.y DSN code.

Writes the 'T' line to RESULTS to tell the C code to tempfail
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_tempfail
{
        my ($self, $reply, $code, $dsn) = @_;
        return 0 unless $self->in_message_context();
        if ($self->was_resent) {
                $self->log('info', 'Refusing to tempfail resent mail');
                return 0;
        }
        $self->tempfailed(1);
        $reply = "Try again later" unless (defined($reply) and ($reply ne ""));
        $code = 451 unless (defined($code) and $code =~ /^4\d\d$/);
        $dsn = "4.3.0" unless (defined($dsn) and $dsn =~ /^4\.\d{1,3}\.\d{1,3}$/);
        $self->_write_result_line('T', $code, $dsn, $reply);
        return 1;
}

=head2 action_change_header($hdr, $value, $idx)

Ask the MTA to change the value of header "$hdr" to "$value".
$idx (if supplied) is the 1-based index of
the header to change in the case of multiple headers.  If "$hdr" was
not present, then the MTA is asked to add it.

Do not include a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_change_header
{
        my ($self, $hdr, $value, $idx) = @_;
        return 0 unless $self->in_message_context();
        $idx = 1 unless defined($idx);
        $self->_log_if_postfix('info', "Header changed: $idx: $hdr: $value");
        $self->_write_result_line('I', $hdr, $idx, $value);
}

=head2 action_delete_header($hdr, $idx)

Ask the MTA to delete the header header "$hdr"
$idx (if supplied) is the 1-based index of the header to
delete in the case of multiple headers.

Do not include a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_delete_header
{
        my ($self, $hdr, $idx) = @_;
        return 0 unless $self->in_message_context();
        $idx = 1 unless defined($idx);
        $self->_log_if_postfix('info', "Header deleted: $idx: $hdr");
        $self->_write_result_line('J', $hdr, $idx);
}

=head2 action_delete_all_headers($hdr)

Ask the MTA to delete all headers "$hdr".  Do not include
a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_delete_all_headers
{
        my ($self, $hdr) = @_;
        return 0 unless $self->in_message_context();
        my $fh;
        if (!open($fh, '<' . Mailmunge::Filter->headers_file())) {
                return undef;
        }
        my $new_hdr = lc($hdr) . ':';
        my $len = length($new_hdr);
        my $count = 0;
        while(<$fh>) {
                $count++ if (lc(substr($_, 0, $len)) eq $new_hdr);
        }
        $fh->close();
        while($count > 0) {
                $self->action_delete_header($hdr, $count);
                $count--;
        }
        return 1;
}

=head2 change_sender($sender)

Asks the MTA to change the envelope sender

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub change_sender
{
        my ($self, $sender) = @_;
        return 0 unless $self->in_message_context();
        $self->_log_if_postfix('info', "Sender changed: $sender");
        $self->_write_result_line('f', $sender);
        return 1;
}

=head2 add_recipient($recip)

Asks the MTA to add a recipient to the envelope

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub add_recipient
{
        my ($self, $recip) = @_;
        return 0 unless $self->in_message_context();
        $self->_log_if_postfix('info', "Recipient added: $recip");
        $self->_write_result_line('R', $recip);
        return 1;
}

=head2 delete_recipient($recip)

Asks the MTA to delete $recip from the list of envelope recipients

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub delete_recipient
{
        my ($self, $recip) = @_;
        return 0 unless $self->in_message_context();
        $self->_log_if_postfix('info', "Recipient deleted: $recip");
        $self->_write_result_line('S', $recip);
        return 1;
}

=head2 action_add_header($hdr, $val)

Add a header to the message

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_add_header
{
        my ($self, $hdr, $val) = @_;
        return 0 unless $self->in_message_context();
        $self->_log_if_postfix('info', "Header added: $hdr: $val");
        $self->_write_result_line('H', $hdr, $val);
        return 1;
}

=head2 action_insert_header($hdr, $val, $pos)

Add a header to the message in the specified position.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

As a special case, if C<$pos> is negative or not supplied, then the
header is added at the end, as with C<action_add_header>

=cut
sub action_insert_header
{
        my ($self, $hdr, $val, $pos) = @_;
        return 0 unless $self->in_message_context();

        $pos = -1 unless defined($pos);

        return $self->action_add_header($hdr, $val) if ($pos == -1);
        $self->_log_if_postfix('info', "Header inserted: $pos: $hdr: $val");
        $self->_write_result_line('N', $hdr, $pos, $val);
        return 1;
}

=head2 action_sm_quarantine($reason)

Ask the MTA to quarantine the message.  $reason is the reason for
the quarantine.

Note that this is different from Mailmunge's quarantine function.
Instead, it ends up calling the Milter function smfi_quarantine.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_sm_quarantine
{
        my ($self, $reason) = @_;
        return 0 unless $self->in_message_context();
        $self->_log_if_postfix('info', "Message held in Postfix 'hold' queue");
        return $self->_write_result_line('Q', $reason);
}

=head2 action_quarantine_entire_message($reason)

Quarantines the message in the Mailmunge quarantine directory.  $reason
is the reason for quarantining.  Note that calling this function does
I<not> affect disposition of the message.  If you do not want the original
message delivered, you must call action_bounce or action_discard.

On success, returns the directory in which the message was
quarantined.  On failure, returns undef.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_quarantine_entire_message
{
        my ($self, $msg) = @_;
        return undef unless $self->in_message_context();

        # If it has already been quarantined, we're good
        return $self->message_quarantined if ($self->message_quarantined);

        my $qdir = $self->get_quarantine_dir();
        return undef unless $qdir;

        $self->_write_quarantine_info($qdir);

        if (defined($msg) && ($msg ne '')) {
                if (open(my $fh, ">$qdir/MSG.0")) {
                        $fh->print("$msg\n");
                        $fh->close();
                }
        }
        $self->log('info', "Message quarantined in $qdir");
        $self->copy_or_link(Mailmunge::Filter->inputmsg(), "$qdir/ENTIRE_MESSAGE");
        $self->message_quarantined($qdir);
        return $qdir;
}

=head2 copy_or_link($src, $dst)

Attempt to hard-link the file $src to $dst.  $dst must be the full desired
path of the destination.  If hard-linking fails, copy the file instead.

Returns 1 on success; 0 on failure.

=cut
sub copy_or_link
{
        my ($self, $src, $dst) = @_;

        # Try linking
        return 1 if link($src, $dst);

        # Otherwise copy
        my $ret = 0;
        if (open(my $ifh, "<$src")) {
                if (open(my $ofh, ">$dst")) {
                        my ($n, $string);
                        while(($n = read($ifh, $string, 4096)) > 0) {
                                print $ofh $string;
                        }
                        $ret = 1 if ($ofh->close());
                }
                $ifh->close();
        }
        return $ret;
}

__PACKAGE__->make_accessors(@accessors);

1;

__END__

=head1 NAME

Mailmunge::Context - Object that holds context for Mailmunge
filter callbacks.

=head1 ABSTRACT

Mailmunge::Context holds all of the context for Mailmunge
filter callbacks.  The various pieces of information
available are documented in ACCESSORS.  If you have
a Mailmunge::Context object called $ctx and you want
to access the "subject" and "sender" accessors (for example), use this
code:

    my $subject = $ctx->subject;
    my $sender = $ctx->sender;

You can also set values in the context by calling (for example)

    $ctx->subject($new_subject);
    $ctx->sender($new_sender);

although the usefulness of doing this is dubious as the new value is
not propagated back to the milter.  One exception to this rule is if
you want to replace the message body.  From C<filter_message>, you can
call:

    $ctx->new_mime_entity($new_entity);

which will replace the message body with $new_entity.  Setting
C<new_mime_entity> also updates C<mime_entity>.

=head1 CLASS METHODS

=head2 Mailmunge::Context->new([$param => $val [, $param2 => $val2]...])

Mailmunge::Context constructor.  Typically not called by user code;
the base filter code takes care of creating Mailmunge::Context object

=head1 ACCESSORS

=head2 bounced

Returns a true value if C<action_bounce> has been called.
Available in: C<filter_message>, C<filter_wrapup>

=head2 client_port

The TCP port of the connecting SMTP client.
Available in: C<filter_relay>, C<filter_helo>

=head2 connecting_ip

The IP address of the connecting SMTP client.
Available in: All filter callbacks.

=head2 connecting_name

The hostname of the connecting SMTP client, if
it passed round-trip reverse DNS.  Otherwise,
the connecting IP address in square brackets.
Available in: All filter callbacks.

=head2 cwd

The current working directory in which
filter files reside.
Available in: C<filter_sender>, C<filter_recipient>,
C<filter_message>, and C<filter_wrapup>

=head2 discarded

Returns a true value if C<action_discard> has been called.
Available in: C<filter_message>, C<filter_wrapup>

=head2 emstp_args

An array reference containing the ESMTP arguments (if any) given to
the MAIL From: command

Available in C<filter_sender>, C<filter_recipient>, C<filter_message>
and C<filter_wrapup>

=head2 first_recip

The mailbox given by the I<first> RCPT To: command for this message.
Available only in C<filter_recipient>

=head2 helo

The hostname given in the HELO or EHLO command.  Available in
C<filter_helo>, C<filter_sender>, C<filter_recipient>, C<filter_message>
and C<filter_wrapup>.

=head2 hostip

The IP address of the host from which this email originated.
In C<filter_relay>, C<filter_helo>, C<filter_sender>
and C<filter_recipient>, this accessor is available and is exactly
the same as connecting_ip.  In C<filter_message> and C<filter_wrapup>,
it is available but I<may differ> from connecting_ip if it was parsed
from the message headers.

=head2 hostname

The name of the host from which this email originated, if it
could be determined, or "[hostip]" if not.

In C<filter_relay>, C<filter_helo>, C<filter_sender>
and C<filter_recipient>, this accessor is available and is exactly
the same as connecting_name.  In C<filter_message> and C<filter_wrapup>,
it is available but I<may differ> from connecting_name if it was parsed
from the message headers.

=head2 in_filter_wrapup

Returns true in C<filter_wrapup> and false elsewhere.  Do not tamper
with this value.

=head2 mailmunge_id

A unique identifier for this message.
Available in C<filter_message> and C<filter_wrapup>.

=head2 message_id

The Message-ID as parsed from the Message-ID: header.  Available in
C<filter_message> and C<filter_wrapup>.

=head2 message_quarantined

Returns true if if C<action_quarantine_entire_message> has been called.
Available in C<filter_message> and C<filter_wrapup>.

=head2 mime_entity

Returns a L<MIME::Entity|https://metacpan.org/pod/MIME::Entity> object representing the parsed input mail message.
Available in C<filter_message> and C<filter_wrapup>.

=head2 my_ip

Returns the IP address of the MTA daemon process that accepted the
connection from the SMTP client.
Available in C<filter_relay> and C<filter_helo>.  This information
can be retrieved in C<filter_message> and C<filter_wrapup> with:

    my $ip = $ctx->sendmail_macro('daemon_addr');

=head2 my_port

Returns TCP port of the MTA daemon process that accepted the
connection from the SMTP client.
Available in C<filter_relay> and C<filter_helo>.  This information
can be retrieved in C<filter_message> and C<filter_wrapup> with:

    my $port = $ctx->sendmail_macro('daemon_port');

=head2 qid

Returns the MTA Queue-ID.  While it is available in I<all> callback
functions, it may be set to NOQUEUE in some of them, depending on the
MTA.  If you invoke C<mailmunge> with the -y flag, qid is available in
all callbacks if the MTA is Sendmail.  If the MTA is Postfix, the qid
is only ever reliably available in C<filter_message> and
C<filter_wrapup>

=head2 rcpt_addr

The value of the ${rcpt_addr} Sendmail macro (or Postfix emulated version
thereof).  Available only in C<filter_recipient>.

=head2 rcpt_host

The value of the ${rcpt_host} Sendmail macro (or Postfix emulated version
thereof).  Available only in C<filter_recipient>.

=head2 rcpt_mailer

The value of the ${rcpt_mailer} Sendmail macro (or Postfix emulated version
thereof).  Available only in C<filter_recipient>.

=head2 recipient_esmtp_args

A hash reference indexed by recipient address.  Each element of
the hash is an array reference consisting of the ESMTP rcpt-parameters
as described in RFC 5321, section 4.1.1.3.  recipient_esmtp_args
is available only in C<filter_message> and C<filter_wrapup>.

=head2 recipients

An arrayref of envelope recipient addresses.  In
C<filter_recipient>, it contains a I<single> address (the
address associated with the current RCPT To: command).
In C<filter_message> and C<filter_wrapup>, it contains an array
of all the recipient addresses.

=head2 sender

The envelope address of the sender (the address in the MAIL From: command.)
Available in C<filter_sender>, C<filter_recipient>, C<filter_message>
and C<filter_wrapup>.

=head2 subject

The message subject (raw value... not MIME-decoded.)
Available in C<filter_message> and C<filter_wrapup>.

=head2 subject_count

The number of Subject: headers seen in the message.  A message with
more than one Subject: header is somewhat suspicious.
Available in C<filter_message> and C<filter_wrapup>.

=head2 suspicious_chars_in_body

Returns true if a null character, or a carriage return not followed by a
newline, was found in the message body.
Available in C<filter_message> and C<filter_wrapup>.

=head2 suspicious_chars_in_headers

Returns true if a null character, or a carriage return not followed by a
newline, was found in the message headers.
Available in C<filter_message> and C<filter_wrapup>.

=head2 tempfailed

Returns true if C<action_tempfail> was called.
Available in C<filter_message> and C<filter_wrapup>.

=head2 was_resent

Returns true if the message contains a secret IP validation header.
(See L<Mailmunge::Action::Stream/STREAMING MECHANISM> for more details.)
Available in C<filter_message> and C<filter_wrapup>.

=head1 METHODS

C<Mailmunge::Context> has additional methods beyond the accessors.

=head2 new_mime_entity($entity)

Replaces C<mime_entity> with C<$entity> and I<also> signals to
Mailmunge that the MTA should replace the original message with
the new message C<$entity>.

=head2 privdata($key [,$val])

Set or get private data.  This method lets you store additional data
in the context object without interfering with any built-in state.
To set some private data, use:

    $ctx->privdata('my_key', $some_value);

and to retrieve it:

    $some_value = $ctx->privdata('my_key');

The value can be a scalar or reference.  The lifetime of the value is
the same as the lifetime of the $ctx object, which is I<only> for the
current callback; almost all callbacks have a brand-new context
object.  The only exceptions are C<filter_message> and
C<filter_wrapup>, which share a $ctx object.

=head2 in_message_context()

A private function that warns if certain functions are called outside
of C<filter_message> or C<filter_wrapup>.

=head2 message_rejected()

Returns true if C<bounced>, C<discarded> or C<tempfailed> is true.
A quick way to tell if the message won't be delivered is:

    if ($ctx->message_rejected) {
        # Don't bother with expensive processing.
        # Message won't be delivered anyway.
    }

=head2 sendmail_macro($macro)

Retrieve the content of the given sendmail macro.  Don't include
curly braces around long macro names.  For example:

    my $port = $ctx->sendmail_macro('daemon_port');

Sendmail macros are available in C<filter_sender>,
C<filter_recipient>, C<filter_message> and C<filter_wrapup>, although
specific macros may be available only at certain stages.  For example,
with Postfix, the C<i> macro is not available until the I<second> call
to C<filter_recipient> (if any) or C<filter_message> if there is only
one recipient.  This is because Postfix does not assign a queue-ID until
after the first successful RCPT command.

=head2 mta_macro($macro)

A synonym for C<sendmail_macro>.

=head2 get_recipient_mailer($recip)

Returns the [mailer, host, addr] triplet associated with the given
recipient, from the Sendail macros {rcpt_mailer}, {rcpt_host} and
{rcpt_addr}.  Available in C<filter_message> and C<filter_wrapup>.

=head2 get_quarantine_dir()

Creates a brand-new subdirectory under Mailmunge's quarantine
directory.  If the Path:QUARANTINEDIR constant is not set, or the directory
could not be created, returns undef.  Otherwise, returns the full
path to the directory

=head2 canonical_sender()

Returns Mailmunge::Filter->canonical_email($self->sender)

=head2 canonical_recipients()

Returns an arrayref of envelope recipient addresses after passing them
through Mailmunge::Filter->canonical_email

=head2 log($level, $msgs)

Log a message to syslog of the specified level.  $level must be one
of 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info' or 'debug'

=cut

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.

=head1 SEE ALSO

L<Mailmunge::Filter>, L<Mailmunge::Response>, L<mailmunge>, L<mailmunge-multiplexor>
