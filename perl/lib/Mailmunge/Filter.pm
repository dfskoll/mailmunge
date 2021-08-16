use strict;
use warnings;

package main;
# This singleton, unfortunately, is needed for the embedded Perl code
# to find and run the filter

our $MAILMUNGE_FILTER;

=head1 NAME

Mailmunge::Filter - base class for Mailmunge filtering

=head1 ABSTRACT

This is the base class for all filters.  Implement your own filtering
policy by subclassing Mailmunge::Filter and overriding various functions
to implement your policy.

=head1 SYNOPSIS

    package MyFilter;
    use base qw(Mailmunge::Filter);

    sub filter_relay {
        # ... implement your policy
    }

    my $filter = MyFilter->new();
    $filter->run();

    1;

=cut

# This function is defined in the I<main> package!
#
# Run the registered filter's main loop.  This should
# I<never> be called directly; only the embedded Perl code
# inside C<mailmunge-multiplexor> calls this function.

sub _mailmunge_do_main_loop
{
        unless ($MAILMUNGE_FILTER) {
                print STDERR "No filter has been registered.\n";
                print STDERR "Check your filter file for syntax errors by running it through\n";
                print STDERR "perl -c\n";
                exit(42);
        }
        return $MAILMUNGE_FILTER->_main_loop();
}

package Mailmunge::Filter;

use Mailmunge::Constants;
use Mailmunge::Response;
use Mailmunge::Context;
use Mailmunge;

use MIME::Parser;

use Sys::Syslog;
use Sys::Hostname;
use Time::Local;

# For getaddrinfo, etc.
use Socket qw(:addrinfo SOCK_RAW);


=head1 CLASS METHODS

Class methods may be called either as C<Mailmunge::Filter-E<gt>method(...)>
or C<$filter-E<gt>method(...)>, where C<$filter> is an instance of
C<Mailmunge::Filter> or some derived class.

=head2 Mailmunge::Filter->new

Construct a new Mailmunge::Filter object and parse the command-line
arguments to determine whether or not to update status tags
and to enter the main loop.

=cut
sub new
{
        my ($class) = @_;
        my $self = bless {
                do_status_tags => 0,
                enter_main_loop => 0,
                status_tags => [],
        }, $class;
        $self->_parse_cmdline_args();

        return $self;
}

=head2 ip_to_hostname ($ip [, $fcrdns])

Converts a human-readable IPv4 or IPv6 to a hostname if reverse-dns
exists.  If it does not reverse-resolve, returns "[$ip]"

If $fcrdns is true (the default if not supplied), then this function
performs Forward-confirmed reverse DNS to make sure that the hostname
include $ip in one of its forward-resolving records.  If FCrDNS fails,
then "[$ip]" is returned.

=cut
sub ip_to_hostname
{
        my ($self, $ip, $fcrdns) = @_;

        $fcrdns = 1 unless defined($fcrdns);

        my ($err, @res);

        ($err, @res) = getaddrinfo($ip, '', {socktype => SOCK_RAW});
        return "[$ip]" if $err;

        my $found;
        my $found_ai;
        foreach my $ai (@res) {
                my ($err, $host) = getnameinfo($ai->{addr}, 0, NIx_NOSERV);
                next if $err;
                $found = $host;
                $found_ai = $ai;
                last;
        }
        return "[$ip]" unless defined($found);
        return $found unless $fcrdns;

        # Caller asked for FCrDNS
        ($err, @res) = getaddrinfo($found, '', {socktype => SOCK_RAW});
        return "[$ip]" if $err;

        foreach my $ai (@res) {
                return $found if ($ai->{addr} eq $found_ai->{addr});
        }

        # FCrDNS failed; don't return hostname
        return "[$ip]";
}

=head2 mailmunge_version

Returns the version of Mailmunge as a string.

=cut
sub mailmunge_version
{
        return $Mailmunge::VERSION;
}

=head2 log_identifier()

Returns C<mailmunge-filter> and is used as the syslog program identifier.  Derived
classes can override this if they wish.

=cut
sub log_identifier { return 'mailmunge-filter'; }

=head2 log_options()

Returnc C<pid,ndelay>, passed as the option parameter
to C<openlog> in C<Sys::Syslog>.  Derived classes can override this if
they wish.

=cut
sub log_options    { return 'pid,ndelay';    }

=head2 log_facility()

Returns C<mail>, the default syslog facility.  Derived classes can
override this to log using a different facility.

=cut
sub log_facility   { return 'mail';          }

# Private function: _ensure_response
# Ensure we have a Mailmunge::Response object.  If not, replace it
# with a tempfail response object.

sub _ensure_response
{
        my ($self, $ctx, $resp, $func) = @_;
        return $resp if (eval { $resp->isa('Mailmunge::Response') } );
        $self->log($ctx, 'err', "$func did NOT return a Mailmunge::Response object!  Check your filter code; tempfailing");
        return Mailmunge::Response->TEMPFAIL(message => 'Internal software error');
}

# Private function: _init_logging
# Initialize Sys::Syslog so we can log
sub _init_logging
{
        my ($self) = @_;
        openlog($self->log_identifier, $self->log_options, $self->log_facility);
}

=head2 canonical_email($email)

Returns $email all lower-case with leading or trailing angle-brackets stripped

=cut
sub canonical_email
{
        my ($self, $email) = @_;
        $email = lc($email);
        $email =~ s/^<//;
        $email =~ s/>$//;
        return $email;
}

=head2 action_from_response ($ctx, $resp)

Given a L<Mailmunge::Response> object C<$resp>, take the appropriate action.
This function operates as follows:

=over

If C<$resp-E<gt>is_tempfail>, call C<$self-E<gt>action_tempfail($ctx, $resp-E<gt>message)> and return 1

If C<$resp-E<gt>is_reject>, call C<$self-E<gt>action_bounce($ctx, $resp-E<gt>message)> and return 1

If C<$resp-E<gt>is_discard>, call C<$self-E<gt>action_discard($ctx)> and return 1

Otherwise, return 0.

=back

=cut
sub action_from_response
{
        my ($self, $ctx, $resp) = @_;

        if ($resp->is_tempfail) {
                $self->action_tempfail($ctx, $resp->message);
                return 1;
        }

        if ($resp->is_reject) {
                $self->action_bounce($ctx, $resp->message);
                return 1;
        }

        if ($resp->is_discard) {
                $self->action_discard($ctx);
                return 1;
        }

        # Didn't do anything
        return 0;
}

=head2 domain_of($email)

Return the domain part of $email

=cut
sub domain_of
{
        my ($self, $email) = @_;
        $email = $self->canonical_email($email);
        $email =~ s/.*@//;
        return $email;
}

=head2 mta_is_postfix ()

Returns true if the MTA is Postfix; false if not (or could not be determined)

=cut
my $MTA_IS_POSTFIX;
my $MTA_IS_SENDMAIL;

sub mta_is_postfix
{
        return $MTA_IS_POSTFIX if defined($MTA_IS_POSTFIX);

        # Try avoiding execution of "sendmail" because Postfix logs
        # warnings if invoked with -bt.  So look for a likely
        # way to distinguish by checking for /etc/postfix/main.cf
        # vs /etc/mail/sendmail.cf
        if (-r "/etc/postfix/main.cf" && ! -r "/etc/mail/sendmail.cf") {
                $MTA_IS_POSTFIX = 1;
                $MTA_IS_SENDMAIL = 0;
                return 1;
        }
        if (!-r "/etc/postfix/main.cf" && -r "/etc/mail/sendmail.cf") {
                $MTA_IS_POSTFIX = 0;
                $MTA_IS_SENDMAIL = 1;
                return 0;
        }

        my $sm = Mailmunge::Constants->get_program_path('sendmail');
        if (!$sm) {
                $MTA_IS_POSTFIX = 0;
                return 0;
        }
        if (open(IN, "$sm -bt < /dev/null 2>&1|")) {
                while(<IN>) {
                        if (/unsupported: -bt/i) {
                                $MTA_IS_POSTFIX = 1;
                                $MTA_IS_SENDMAIL = 0;
                                close(IN);
                                return 1;
                        } elsif (/address test mode/i) {
                                $MTA_IS_POSTFIX = 0;
                                $MTA_IS_SENDMAIL = 1;
                                close(IN);
                                return 0;
                        }
                }
                close(IN);
        }

        # We dunno what we have...
        $MTA_IS_POSTFIX = 0;
        $MTA_IS_SENDMAIL = 0;
        return 0;
}

=head2 mta_is_sendmail ()

Returns true if the MTA is Sendmail; false if not (or could not be determined)

=cut
sub mta_is_sendmail
{
        my ($self) = @_;

        # Do the actual work to set the MTA variables...
        $self->mta_is_postfix() unless defined $MTA_IS_SENDMAIL;
        return $MTA_IS_SENDMAIL;
}

=head1 INSTANCE METHODS

=head2 log($ctx, $level, $msg)

Log a message to syslog of the specified level.  $level must be one
of 'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info' or 'debug'
$ctx is either an Mailmunge::Context object, or a string representing a Queue-ID.

=cut
sub log
{
        my ($self, $ctx, $level, $msg) = @_;

        # Accept either a queue ID or an Mailmunge::Context object
        my $qid = $ctx;
        $qid = $ctx->qid if ref($ctx);

        if (defined($qid) && $qid ne 'NOQUEUE' && $qid ne '') {
                syslog($level, '%s', $qid . ': ' . $msg);
        } else {
                syslog($level, '%s', $msg);
        }
}

# Private function: _register
# Register the filter so that the embedded Perl code can invoke its
# main_loop correctly.
no warnings 'once';
sub _register
{
        my ($self) = @_;
        die("Filter already registered") if $::main::FILTER;
        $::main::MAILMUNGE_FILTER = $self;
}
use warnings 'once';

=head2 run()

Run the filter.  In server mode, starts the server main loop.  In embedded
mode, registers the filter in a global variable and returns; the
multiplexor will start the server main loop at an appropriate time.

=cut
sub run
{
        my ($self) = @_;

        $self->prefork_initialize();

        return $self->_main_loop() if $self->{enter_main_loop};

        # Running under embedded Perl; just register
        # and return.
        $self->_register();

        return 0;
}

# Private function: Change to the Mailmunge spool directory.
sub _cd_to_spooldir
{
        my ($spooldir) = Mailmunge::Constants->get('Path:SPOOLDIR');
        chdir($spooldir) if defined($spooldir);
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
# _write_result_line($ctx, $cmd, @args)
# Writes the line to RESULTS, percent-escaping each member of @args.
sub _write_result_line
{
        my $self = shift;
        my $ctx  = shift;
        my $cmd  = shift;

        my $fh = $self->_results_fh();

        my $line = $cmd . join(' ', map { $self->_percent_encode($_) } (@_));
	# We have an 8kb limit on the length of lines in RESULTS, including
	# trailing newline and null used in the milter.  So, we limit $cmd +
	# $args to 8190 bytes.
	if( length $line > 8190 ) {
		$self->log( $ctx, 'warning',  "Cannot write line over 8190 bytes long to RESULTS file; truncating.  Original line began with: " . substr $line, 0, 40);
		$line = substr $line, 0, 8190;
	}
        print $fh "$line\n" or die("Could not write RESULTS line: $!");
}

# Private function
# Writes the 'F' command to RESULTS and closes the RESULTS
# filehandle.
sub _signal_complete
{
        my ($self, $ctx) = @_;
        $self->_write_result_line($ctx, 'F');
        $self->_close_results_fh();
}

# Private function
# Log only if the MTA is Postfix.  Sendmail
# is much more verbose about logging Milter
# events than Postfix, so we do additional
# logging if the MTA is Postfix.
sub _log_if_postfix
{
        my ($self, $ctx, $level, $msg) = @_;
        return unless $self->mta_is_postfix();
        $self->log($ctx, $level, $msg);
}

# Private function
# Writes the 'C' command to RESULTS to tell the C code to replace
# the message body
sub _signal_changed
{
        my ($self, $ctx) = @_;
        $self->_log_if_postfix($ctx, 'info', 'Message body replaced');
        $self->_write_result_line($ctx, 'C');
}

=head2 action_bounce($ctx, $reply, $code, $dsn)

Ask the MTA to bounce the message.  $ctx is the Mailmunge::Context object;
$reply is the text of the bounce; code is a 3-digit 5xy reply code,
and $dsn is a three-numbered 5.x.y DSN code.

Writes the 'B' line to RESULTS to tell the C code to bounce
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_bounce
{
        my ($self, $ctx, $reply, $code, $dsn) = @_;
        return 0 unless $ctx->in_message_context($self);

        # Convert bounce to discard for resent mail
        if ($ctx->was_resent) {
                $self->log($ctx, 'info', 'Converting "bounce" to "discard" for resent mail');
                return $self->action_discard($ctx);
        }

        $ctx->bounced(1);
        $reply = "Forbidden for policy reasons" unless (defined($reply) and ($reply ne ""));
        $code = 554 unless (defined($code) and $code =~ /^5\d\d$/);
        $dsn = "5.7.1" unless (defined($dsn) and $dsn =~ /^5\.\d{1,3}\.\d{1,3}$/);

        $self->_write_result_line($ctx, 'B', $code, $dsn, $reply);
        return 1;
}

=head2 action_discard($ctx)

Ask the MTA to discard the message.  $ctx is the Mailmunge::Context object.

Writes the 'D' line to RESULTS to tell the C code to discard
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_discard
{
        my ($self, $ctx) = @_;
        return 0 unless $ctx->in_message_context($self);
        $ctx->discarded(1);
        $self->_write_result_line($ctx, 'D', '');
        return 1;
}

=head2 action_tempfail($ctx, $reply, $code, $dsn)

Ask the MTA to tempfail the message.  $ctx is the Mailmunge::Context object;
$reply is the text of the tempfail response; code is a 3-digit 4xy
reply code, and $dsn is a three-numbered 4.x.y DSN code.

Writes the 'T' line to RESULTS to tell the C code to tempfail
the message.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_tempfail
{
        my ($self, $ctx, $reply, $code, $dsn) = @_;
        return 0 unless $ctx->in_message_context($self);
        if ($ctx->was_resent) {
                $self->log($ctx, 'info', 'Refusing to tempfail resent mail');
                return 0;
        }
        $ctx->tempfailed(1);
        $reply = "Try again later" unless (defined($reply) and ($reply ne ""));
        $code = 451 unless (defined($code) and $code =~ /^4\d\d$/);
        $dsn = "4.3.0" unless (defined($dsn) and $dsn =~ /^4\.\d{1,3}\.\d{1,3}$/);
        $self->_write_result_line($ctx, 'T', $code, $dsn, $reply);
        return 1;
}

=head2 action_change_header($ctx, $hdr, $value, $idx)

Ask the MTA to change the value of header "$hdr" to "$value".  $ctx is
the Mailmunge::Context object, and $idx (if supplied) is the 1-based index of
the header to change in the case of multiple headers.  If "$hdr" was
not present, then the MTA is asked to add it.

Do not include a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_change_header
{
        my ($self, $ctx, $hdr, $value, $idx) = @_;
        return 0 unless $ctx->in_message_context($self);
        $idx = 1 unless defined($idx);
        $self->_log_if_postfix($ctx, 'info', "Header changed: $idx: $hdr: $value");
        $self->_write_result_line($ctx, 'I', $hdr, $idx, $value);
}

=head2 action_delete_header($ctx, $hdr, $idx)

Ask the MTA to delete the header header "$hdr" $ctx is the Mailmunge::Context
object, and $idx (if supplied) is the 1-based index of the header to
delete in the case of multiple headers.

Do not include a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_delete_header
{
        my ($self, $ctx, $hdr, $idx) = @_;
        return 0 unless $ctx->in_message_context($self);
        $idx = 1 unless defined($idx);
        $self->_log_if_postfix($ctx, 'info', "Header deleted: $idx: $hdr");
        $self->_write_result_line($ctx, 'J', $hdr, $idx);
}

=head2 action_delete_all_headers($ctx, $hdr)

Ask the MTA to delete all headers "$hdr".  Do not include
a colon in the header name.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_delete_all_headers
{
        my ($self, $ctx, $hdr) = @_;
        return 0 unless $ctx->in_message_context($self);
        my $fh;
        if (!open($fh, '<' . $self->headers_file())) {
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
                $self->action_delete_header($ctx, $hdr, $count);
                $count--;
        }
        return 1;
}

=head2 change_sender($ctx, $sender)

Asks the MTA to change the envelope sender

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub change_sender
{
        my ($self, $ctx, $sender) = @_;
        return 0 unless $ctx->in_message_context($self);
        $self->_log_if_postfix($ctx, 'info', "Sender changed: $sender");
        $self->_write_result_line($ctx, 'f', $sender);
        return 1;
}

=head2 add_recipient($ctx, $recip)

Asks the MTA to add a recipient to the envelope

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub add_recipient
{
        my ($self, $ctx, $recip) = @_;
        return 0 unless $ctx->in_message_context($self);
        $self->_log_if_postfix($ctx, 'info', "Recipient added: $recip");
        $self->_write_result_line($ctx, 'R', $recip);
        return 1;
}

=head2 delete_recipient($ctx, $recip)

Asks the MTA to delete $recip from the list of envelope recipients

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub delete_recipient
{
        my ($self, $ctx, $recip) = @_;
        return 0 unless $ctx->in_message_context($self);
        $self->_log_if_postfix($ctx, 'info', "Recipient deleted: $recip");
        $self->_write_result_line($ctx, 'S', $recip);
        return 1;
}

=head2 action_add_header($ctx, $hdr, $val)

Add a header to the message

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_add_header
{
        my ($self, $ctx, $hdr, $val) = @_;
        return 0 unless $ctx->in_message_context($self);
        $self->_log_if_postfix($ctx, 'info', "Header added: $hdr: $val");
        $self->_write_result_line($ctx, 'H', $hdr, $val);
        return 1;
}

=head2 action_insert_header($ctx, $hdr, $val, $pos)

Add a header to the message in the specified position.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_insert_header
{
        my ($self, $ctx, $hdr, $val, $pos) = @_;
        return 0 unless $ctx->in_message_context($self);
        $pos = 0 unless defined($pos);
        $self->_log_if_postfix($ctx, 'info', "Header inserted: $pos: $hdr: $val");
        $self->_write_result_line($ctx, 'N', $hdr, $pos, $val);
        return 1;
}

=head2 action_sm_quarantine($ctx, $reson)

Ask the MTA to quarantine the message.  $reason is the reason for
the quarantine.

Note that this is different from Mailmunge's quarantine function.
Instead, it ends up calling the Milter function smfi_quarantine.

This method may only be called from C<filter_message> or
C<filter_wrapup> (or from functions called while they are active.)

=cut
sub action_sm_quarantine
{
        my ($self, $ctx, $reason) = @_;
        return 0 unless $ctx->in_message_context($self);
        $self->_log_if_postfix($ctx, 'info', "Message held in Postfix 'hold' queue");
        return $self->_write_result_line($ctx, 'Q', $reason);
}

=head2 action_quarantine_entire_message($ctx, $reason)

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
        my ($self, $ctx, $msg) = @_;
        return undef unless $ctx->in_message_context($self);

        # If it has already been quarantined, we're good
        return $ctx->message_quarantined if ($ctx->message_quarantined);

        my $qdir = $ctx->get_quarantine_dir();
        return undef unless $qdir;

        $ctx->_write_quarantine_info($self, $qdir);

        if (defined($msg) && ($msg ne '')) {
                if (open(my $fh, ">$qdir/MSG.0")) {
                        $fh->print("$msg\n");
                        $fh->close();
                }
        }
        $self->log($ctx, 'info', "Message quarantined in $qdir");
        $self->copy_or_link($self->inputmsg(), "$qdir/ENTIRE_MESSAGE");
        $ctx->message_quarantined($qdir);
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


# Private function: _parse_cmdline_args()
# Parses out the operating mode from the command-line arguments
sub _parse_cmdline_args {
        my ($self) = @_;
        my $seen = 0;
        foreach my $arg (@ARGV) {
                if ($arg eq '-server') {
                        $seen = 1;
                        $self->{enter_main_loop} = 1;
                } elsif ($arg eq '-serveru') {
                        $seen = 1;
                        $self->{do_status_tags} = 1;
                        $self->{enter_main_loop} = 1;
                } elsif ($arg eq '-embserver') {
                        $seen = 1;
                } elsif ($arg eq '-embserveru') {
                        $seen = 1;
                        $self->{do_status_tags} = 1;
                } elsif ($arg eq '-f') {
                        print STDERR "-f option is deprecated and ignored.\n";
                }
        }
        $self->_missing_cmdline_args("Usage: $0 -server|-serveru|-embserver|-embserveru") unless $seen;

        # Open the file handle for status updates, if we
        # are doing those.
        if ($self->{do_status_tags}) {
                my $fh;
                if (open($fh, '>&=3')) {
                        $fh->autoflush(1);
                        $self->{status_handle} = $fh;
                } else {
                        $self->{do_status_tags} = 0;
                }
        }
}

# Private function: _missing_cmdline_args()
# Called if we cannot set the operating mode.  By default,
# prints an error message and exits.  May be overridden for
# test purposes.
sub _missing_cmdline_args
{
        my ($self, $msg) = @_;
        # Do nothing if we're running in a test harness
        return if $ENV{'HARNESS_ACTIVE'};

        print STDERR "*** NOTE: You should not run $0 directly.\n";
        print STDERR "*** It should only be run by mailmunge-multiplexor.\n";
        print STDERR "$msg\n";
        exit(1);
}

# Private function: _main_loop()
#
# The main loop of the filter.  Initialize, and then wait for commands
# from the multiplexor.  You should not call this directly!  Instead,
# call run()
sub _main_loop
{
        my ($self) = @_;

        $self->_init_logging();

        $self->_cd_to_spooldir();

        $self->initialize();

        if ($self->mta_is_postfix) {
                $self->log('NOQUEUE', 'info', 'MTA appears to be: Postfix');
        } elsif ($self->mta_is_sendmail) {
                $self->log('NOQUEUE', 'info', 'MTA appears to be: Sendmail');
        } else {
                $self->log('NOQUEUE', 'info', 'MTA could not be identified');
        }

        while (my $line = <STDIN>) {
                $self->_cd_to_spooldir();
                chomp($line);

                my ($cmd, @args) = map { $self->_percent_decode($_) } split(/\s+/, $line);
                $cmd = lc $cmd;

                if ($self->can("_handle_$cmd")) {
                        $cmd = "_handle_$cmd";
                        $self->$cmd(@args);
                } else {
                        my $resp = $self->unknown_command($cmd, @args);
                        $resp = $self->_ensure_response('NOQUEUE', $resp, 'unknown_command');
                        $self->_reply_with_status(undef, $resp, 'unkown_command');
                }
        }

        my $ret = $self->cleanup();
        if (!defined($ret)) {
                $self->log('NOQUEUE', "Warning: Your filter's cleanup() function returned undef; it must return an integer");
                $ret = 0;
        } elsif ($ret !~ /^-?\d+$/) {
                $self->log('NOQUEUE', "Warning: Your filter's cleanup() function returned '$ret'; it must return an integer");
                $ret = 0;
        }
        exit($ret);
}

# Private function: reply_to_mx($msg)
#
# Print "$msg\n" to stdout and flush.  This replies to
# the multiplexor.
sub _reply_to_mx
{
        my ($self, $msg) = @_;
        STDOUT->printflush("$msg\n");
}

# Private function: reply_error($msg)
# Equivalent to: reply_to_mx("error: $msg");
sub _reply_error
{
        my ($self, $msg) = @_;
        if ($msg) {
                $self->_reply_to_mx("error: $msg");
        } else {
                $self->_reply_to_mx("error:");
        }
}

# Private function: reply_ok($msg)
# Equivalent to: reply_to_mx("ok $msg");
sub _reply_ok
{
        my ($self, $msg) = @_;
        if ($msg) {
                $self->_reply_to_mx("ok $msg");
        } else {
                $self->_reply_to_mx("ok");
        }
}

# Private function: reply_array @args
#
#Percent-encodes each argument of @args and joins them with spaces;
#then calls reply_to_mx($result)
sub _reply_array
{
        my ($self, @args) = @_;
        return $self->_reply_to_mx(join(' ', map { $self->_percent_encode($_, '?') } (@args)));
}

# Private function: reply_with_status($ctx, $resp, $what)
# $ctx is an Mailmunge::Context object
# $resp is an Mailmunge::Response object
# $what is additional text to log.
#
# Replies with the appropriate code to tell Mailmunge to
# accept, reject, tempfail, etc. the given milter callback,
# which is one of xxfi_connect, xxfi_helo, xxfi_envfrom or
# xxfi_envrcpt
sub _reply_with_status
{
        my ($self, $ctx, $resp, $what) = @_;

        $resp->fix_code_dsn();

        my $status = $resp->status;

        if ($status eq 'ACCEPT_AND_NO_MORE_FILTERING') {
                $self->log($ctx, 'debug', "ACCEPT_AND_NO_MORE_FILTERING: No further filtering for this message");
                return $self->_reply_array('ok', '2', $resp->message, $resp->code, $resp->dsn, $resp->delay);
        }

        if ($status eq 'DISCARD') {
                $self->log($ctx, 'info', "DISCARD: Discarding this message");
                return $self->_reply_array('ok', '3', $resp->message, $resp->code, $resp->dsn, $resp->delay);
        }

        if ($status eq 'CONTINUE') {
                return $self->_reply_array('ok', '1', $resp->message, $resp->code, $resp->dsn, $resp->delay);
        }

        if ($status eq 'REJECT') {
                $self->log($ctx, 'debug', "REJECT: rejected $what");
                return $self->_reply_array('ok', '0', $resp->message, $resp->code, $resp->dsn, $resp->delay);
        }


        # Default to TEMPFAIL
        if ($status ne 'TEMPFAIL') {
                $self->log($ctx, 'warning', "Unknown code $status given to reply_with_status: Converting to TEMPFAIL");
        }
        $self->log($ctx, 'debug', "TEMPFAIL: tempfailed $what");
        return $self->_reply_array('ok', '-1', $resp->message, $resp->code, $resp->dsn, $resp->delay);
}

=head2 unknown_command($cmd, @args)

Called when we get an unknown command.  By default, returns an error
to the multiplexor.  Subclasses can override this method to do something
useful.

=cut
sub unknown_command
{
        my ($self, $cmd, @args) = @_;
        return Mailmunge::Response->REJECT(message => 'Unknown command');
}


# Pathnames of various files written by the milter.
# Implemented as methods so test code can override if necessary

=head2 inputmsg()

Returns the relative path to the input message file received
from the MTA

=cut
sub inputmsg         { return 'INPUTMSG'; }

sub _newbody          { return 'NEWBODY'; }

=head2 headers_file()

Returns the relative path to the HEADERS file.  This file contains
only the top-level headers of the email message.  The headers
are unwrapped, so this file is guaranteed to contain exactly one
header per line.

=cut

sub headers_file     { return 'HEADERS'; }
sub _commands_file    { return 'COMMANDS'; }

=head2 product_name()

Returns 'Mailmunge'.  Derived classes may override this if they wish.

=cut
sub product_name     { return 'Mailmunge'; }

=head2 spooldir()

Returns the full path to the Mailmunge spool directory.  Exactly
equivalent to C<Mailmunge::Constants-E<gt>get('Path:SPOOLDIR')>.

=cut
sub spooldir         { return Mailmunge::Constants->get('Path:SPOOLDIR'); }

=head2 inputmsg_absolute($ctx)

Returns the absolute path to the input message file received
from the MTA.  This is the path that should be passed to
virus-scanners, for example.

=cut
sub inputmsg_absolute
{
        my ($self, $ctx) = @_;
        return $ctx->cwd . '/' . $self->inputmsg;
}

#
# Stubs that should be overridden by subclasses
#

=head2 tick($tick_number)

This method is called periodically by the multiplexor if given
the "-X interval" option.  It should be overridden in a derived
class and should return 1.  The base class implementation does
nothing and returns 0, causing a warning to be logged.

Note that the "tick" functionality of Mailmunge is deprecated.

=cut
sub tick             { return 0; }

=head2 filter_map($map, $key)

Look up the key $key in the map named $map.  Return an array that looks
like one of the following:

    ('PERM', 'Permanent failure message')
    ('TEMP', 'Temporary failure message')
    ('TIMEOUT', 'Timeout message')
    ('OK', 'Result-Of-Lookup')
    ('NOTFOUND', '')

The base class implementation simply returns:

    ('PERM', 'Filter does not implement map method')

=cut
sub filter_map       { return ('PERM', 'Filter does not implement map method'); }

=head2 filter_relay ($ctx)

$ctx is an Mailmunge::Context object.  This method is called as part of the
xxfi_connect Milter callback, when a remote machine attempts to connect.
It should be overridden by a derived class.

The following $ctx fields are available:

    $ctx->hostip       IP address of connecting host
    $ctx->hostname     Hostname of the connecting host
    $ctx->client_port  Client TCP port
    $ctx->my_ip        Server's IP address
    $ctx->my_port      Server's TCP port
    $ctx->qid          Queue ID (Note: May be NOQUEUE if queue ID not available)

The function must return an Mailmunge::Response object instructing the MTA how
to handle the callback.

The default base class method returns Mailmunge::Response->CONTINUE().

=cut
sub filter_relay     { return Mailmunge::Response->CONTINUE(); }

=head2 filter_helo ($ctx)

$ctx is an Mailmunge::Context object.  This method is called as part of the
xxfi_helo Milter callback, when a remote machine issues a HELO/EHLO command.
It should be overridden by a derived class.

The following $ctx fields are available:

    $ctx->hostip       IP address of connecting host
    $ctx->hostname     Hostname of the connecting host
    $ctx->helo         The argument to the EHLO/HELO command
    $ctx->client_port  Client TCP port
    $ctx->my_ip        Server's IP address
    $ctx->my_port      Server's TCP port
    $ctx->qid          Queue ID (Note: May be NOQUEUE if queue ID not available)

The function must return an Mailmunge::Response object instructing the MTA how
to handle the callback.

The default base class method returns Mailmunge::Response->CONTINUE().

=cut
sub filter_helo      { return Mailmunge::Response->CONTINUE(); }

=head2 filter_sender ($ctx)

$ctx is an Mailmunge::Context object.  This method is called as part of the
xxfi_envfrom Milter callback, when a remote machine issues a MAIL From: command.
It should be overridden by a derived class.

The following $ctx fields are available:

    $ctx->sender       Envelope sender address
    $ctx->hostip       IP address of connecting host
    $ctx->hostname     Hostname of the connecting host
    $ctx->helo         The argument to the EHLO/HELO command
    $ctx->qid          Queue ID (Note: May be NOQUEUE if queue ID not available)
    $ctx->esmtp_args   Arrayref of ESMTP arguments to MAIL From:
    $ctx->cwd          The current working directory

The function must return an Mailmunge::Response object instructing the MTA how
to handle the callback.

The default base class method returns Mailmunge::Response->CONTINUE().

=cut
sub filter_sender    { return Mailmunge::Response->CONTINUE(); }

=head2 filter_recipient ($ctx)

$ctx is an Mailmunge::Context object.  This method is called as part of the
xxfi_envrcpt Milter callback, when a remote machine issues a RCPT To: command.
It should be overridden by a derived class.

The following $ctx fields are available:

    $ctx->recipients   An arrayref consisting of a single recipient
    $ctx->sender       Envelope sender address
    $ctx->hostip       IP address of connecting host
    $ctx->hostname     Hostname of the connecting host
    $ctx->first_recip  The recipient from the I<first> RCPT To: command
    $ctx->helo         The argument to the EHLO/HELO command
    $ctx->cwd          The current working directory
    $ctx->qid          Queue ID
    $ctx->rcpt_mailer  The ${rcpt_mailer} macro value for this recipient
    $ctx->rcpt_host    The ${rcpt_host} macro value for this recipient
    $ctx->rcpt_addr    The ${rcpt_addr} macro value for this recipient
    $ctx->esmtp_args   Arrayref of ESMTP arguments to MAIL From:

The function must return an Mailmunge::Response object instructing the MTA how
to handle the callback.

The default base class method returns Mailmunge::Response->CONTINUE().

=cut
sub filter_recipient { return Mailmunge::Response->CONTINUE(); }

=head2 filter_message ($ctx)

$ctx is an Mailmunge::Context object.  This method is called when a message
is to be scanned.  The return value of this method is ignored; it
indicates disposition of the message by calling one of the I<action_>
methods.  If no disposition is specified, then the message is delivered.

The following $ctx fields are available; see L<Mailmunge::Context> for details.

    $ctx->connecting_ip
    $ctx->connecting_name
    $ctx->esmtp_args
    $ctx->helo
    $ctx->hostip
    $ctx->hostname
    $ctx->message_id
    $ctx->mime_entity
    $ctx->mailmunge_id
    $ctx->qid
    $ctx->recipients
    $ctx->recipient_esmtp_args
    $ctx->sender
    $ctx->subject
    $ctx->subject_count
    $ctx->suspicious_chars_in_body
    $ctx->suspicious_chars_in_headers
    $ctx->was_resent
    $ctx->cwd

The most important field is probably $ctx->mime_entity, which is the
MIME::Entity representing the message being filtered.  If you replace
the entity by calling:

    $ctx->new_mime_entity($new_entity);

then the MTA will replace the body of the message with the body
of $new_entity.  Setting C<new_mime_entity> also updates C<mime_entity>.

The base class implementation of C<filter_message> does nothing.

=cut
sub filter_message   { return; }

=head2 filter_wrapup ($ctx)

$ctx is an Mailmunge::Context object.  This method is called immediately
after filter_message() and the $ctx object has the same available
fields as in filter_message().

In filter_wrapup, it is not possible to change the message body (that is,
calling C<$ctx-E<gt>new_mime_entity($new_entity)> will have no effect.)

You can only change headers or change the delivery disposition of
the message.  Typically, filter_wrapup is used for something like
DKIM-signing a message.

The base class implementation does nothing.

=cut
sub filter_wrapup    { return; }

=head2 initialize()

This method is called once when the filter process starts up.  It can
be used to establish per-process resources such as database connections.

If you are using an embedded Perl interpreter in mailmunge-multiplexor,
then this function is called I<after> a new scanning process has forked.

The base class implementation does nothing.

NOTE: you should do I<all> per-process initialization in C<initialize()>
and I<not> in top-level Perl functions outside of any method.  The reason
is that if you run the multiplexor using embedded Perl, then C<initialize()>
is called each time a new scanner is forked.  Code outside of methods is
called just once, which may lead to inappropriate sharing of resources
such as filehandles between scanner processes.

To reiterate: I<Do all per-process initialization in $filter-E<gt>initialize()>

=cut
sub initialize       { return; }

=head2 prefork_initialize ()

This function is called once when the C<run()> method is called.  If you
are not using an embedded Perl interpreter in mailmunge-multiplexor, then
C<prefork_initialize()> is called in exactly the same circumstances as
C<initialize()> and there's no point in using it.

If you are using an embedded Perl interpreter, then C<prefork_initialize()>
is called I<once>, before any workers are forked, and can be used to
initialize resources that can be shared across a fork.

The base class implementation does nothing.

=cut
sub prefork_initialize { return; }

=head2 cleanup

This method is called just before the filter process exits.  It is
the cleanup counterpart to initialize(); the return value of this
filter is used as the argument to C<exit()>.

The base class implementation does nothing and returns 0

=cut
sub cleanup          { return 0; }

# Private method: handle_ping
# Handles the PING command by replying PONG
sub _handle_ping
{
        my ($self) = @_;
        $self->_reply_to_mx('PONG');
}

# Private method: handle_map
# Handles the MAP command by calling into $self->filter_map and
# replying appropriately
sub _handle_map
{
        my ($self, $map, $key) = @_;
        my ($code, $val) = $self->filter_map($map, $key);
        $self->_reply_array($code, $val);
}

# Private method: handle_tick
# Handles the TICK command by calling $self->tick() and replying
# appropriately.
sub _handle_tick
{
        my ($self, $tick_no) = @_;
        $tick_no ||= 0;
        if ($self->tick($tick_no)) {
                $self->_reply_array('tock', $tick_no);
        } else {
                $self->_reply_error("tick $tick_no: Filter does not implement tick method");
        }
}

# Private method: handle_relayok
# Handles the relayok command by calling $self->filter_relay() and replying
# appropriately.
sub _handle_relayok
{
        my ($self, $hostip, $hostname, $port, $myip, $myport, $qid) = @_;
        my $ctx = Mailmunge::Context->new(hostip      => $hostip,
                                          hostname    => $hostname,
                                          connecting_ip => $hostip,
                                          connecting_name => $hostname,
                                          client_port => $port,
                                          my_ip       => $myip,
                                          my_port     => $myport,
                                          qid         => $qid);
        my $resp = $self->filter_relay($ctx);
        $resp = $self->_ensure_response($ctx, $resp, 'filter_relay');
        $self->_reply_with_status($ctx, $resp, "host $hostip ($hostname)");
}

# Private method: handle_helook
# Handles the helook command by calling $self->filter_helo() and replying
# appropriately.
sub _handle_helook
{
	my ($self, $hostip, $hostname, $helo, $port, $myip, $myport, $qid) = @_;
        my $ctx = Mailmunge::Context->new(hostip      => $hostip,
                                          hostname    => $hostname,
                                          connecting_ip => $hostip,
                                          connecting_name => $hostname,
                                          helo        => $helo,
                                          client_port => $port,
                                          my_ip       => $myip,
                                          my_port     => $myport,
                                          qid         => $qid);
        my $resp = $self->filter_helo($ctx);
        $resp = $self->_ensure_response($ctx, $resp, 'filter_helo');
        $self->_reply_with_status($ctx, $resp, "helo $helo");
}

# Private method: handle_senderok
# Handles the senderok command by calling $self->filter_sender() and replying
# appropriately.
sub _handle_senderok
{
	my ($self, $sender, $hostip, $hostname, $helo, $cwd, $qid, @esmtp_args) = @_;

	if (!chdir($cwd)) {
                return $self->_reply_with_status($qid, Mailmunge::Response->TEMPFAIL(message => "could not chdir($cwd): $!"),
                                                "sender $sender");
	}

        my $ctx = $self->read_commands_file();
        $ctx->cwd($cwd);
        $ctx->esmtp_args(\@esmtp_args);
	my $resp = $self->filter_sender($ctx);
        $resp = $self->_ensure_response($ctx, $resp, 'filter_sender');
        $self->_reply_with_status($ctx, $resp, "sender $sender");
}

# Private method: handle_recipok
# Handles the recipok command by calling $self->filter_recipient() and replying
# appropriately.
sub _handle_recipok
{
	my ($self, $recipient, $sender, $hostip, $hostname, $first_recip, $helo, $cwd, $qid, $rcpt_mailer, $rcpt_host, $rcpt_addr, @esmtp_args) = @_;

	if (!chdir($cwd)) {
                return $self->_reply_with_status($qid, Mailmunge::Response->TEMPFAIL(message => "could not chdir($cwd): $!"),
                                                "recipient $recipient");
	}
        my $ctx = $self->read_commands_file();
        $ctx->recipients([$recipient]);
        $ctx->first_recip($first_recip);
        $ctx->cwd($cwd);
        $ctx->rcpt_mailer($rcpt_mailer);
        $ctx->rcpt_host($rcpt_host);
        $ctx->rcpt_addr($rcpt_addr);
        $ctx->esmtp_args(\@esmtp_args);

	my $resp = $self->filter_recipient($ctx);

        # If this is Postfix, we cannot tempfail or reject recipients
        # coming into the non_smtpd_milter which we detect with a
        # connecting_ip of 127.0.0.1
        if (($hostip eq '127.0.0.1' || $hostip eq '::1') && $self->mta_is_postfix) {
                if (!$resp->is_success_or_discard) {
                        $self->log($ctx, 'warning', 'Converting ' . $resp->status . " to CONTINUE for Postfix mail on loopback");
                        $resp->status('CONTINUE');
                        $resp->fix_code_dsn();
                }
        }

        $resp = $self->_ensure_response($ctx, $resp, 'filter_recipient');
        $self->_reply_with_status($ctx, $resp, "recipient $recipient");
}

=head2 push_tag($qid, $tag)

Updates the worker status in the multiplexor to be "$tag" with the given
queue-ID.  Only has an effect if the multiplexor was invoked with
the "-Z" option

=cut
sub push_tag
{
        my ($self, $qid, $tag) = @_;
        return unless $self->{do_status_tags};
        push(@{$self->{status_tags}}, $tag);
        if ($tag ne '') {
                $tag = "> $tag";
        }
        $self->_set_tag($qid, scalar(@{$self->{status_tags}}), $tag);
}

=head2 pop_tag($qid)

Restores the previous tag (if any) in effect prior to the corresponding
push_tag call.

=cut
sub pop_tag
{
        my ($self, $qid) = @_;
        return unless $self->{do_status_tags};
        pop(@{$self->{status_tags}});

        my $tag = $self->{status_tags}->[0] || 'no_tag';
        $self->_set_tag($qid, scalar(@{$self->{status_tags}}), $tag);
}

# Private function: _set_tag($qid, $depth, $tag)
# Sets the worker status in the multiplexor.
sub _set_tag
{
        my ($self, $qid, $depth, $tag) = @_;
        return unless $self->{do_status_tags};
        $tag ||= '';
        if ($tag eq '') {
                $self->{status_handle}->print("\n");
                return;
        }
	$tag =~ s/[^[:graph:]]/ /g;

        # If we get a $ctx object, obtain the qid
        if (ref($qid)) {
                $qid = $qid->qid();
        }

	if($qid && ($qid ne 'NOQUEUE')) {
		$self->{status_handle}->print($self->_percent_encode("$depth: $tag $qid") . "\n");
	} else {
		$self->{status_handle}->print($self->_percent_encode("$depth: $tag") . "\n");
	}
}

=head2 read_commands_file($ctx, $need_f)

Reads the COMMANDS file and fills in fields in the Mailmunge::Context object
$ctx.  If $ctx is supplied as undef, then read_commands_file allocates
a new one.

If $need_f is true, then the function fails if the COMMANDS file does
not end with an 'F' command.

Returns $ctx on success (or a newly-allocated Mailmunge::Context if $ctx was
undef); undef on failure.

=cut
sub read_commands_file
{
        my ($self, $ctx, $need_f) = @_;
        my $fh;
        if (!open($fh, "<" . $self->_commands_file())) {
                $self->_signal_complete($ctx);
                $self->_reply_error("Could not open " . $self->_commands_file() . ": $!");
                return undef;
        }
        if (!$ctx) {
                $ctx = Mailmunge::Context->new();
        }

        $ctx = $ctx->_read_command_filehandle($self, $fh, $need_f);
        return $ctx;
}

# Private function: _percent_encode($str, $default)
# Escapes unsafe characters in $str by encoding them as %XY where
# X and Y are hex characters.  If $str is blank or undef, $default
# is encoded instead.
sub _percent_encode
{
        my ($self, $str, $default) = @_;
        if (!defined($str) || ($str eq '')) {
                $str = $default || '';
        }

        $str =~ s/([^\x21-\x7e]|[%\\'"])/sprintf("%%%02X", unpack("C", $1))/ge;
        return $str;
}

# Private function: _percent_decode($str, $default) The inverse of
# _percent_encode.  If $str is blank or undef, $default is decoded
# instead.
sub _percent_decode
{
        my ($self, $str, $default) = @_;

        if (!defined($str) || ($str eq '')) {
                $str = $default || '';
        }
        $str =~ s/%([0-9A-Fa-f]{2})/pack("C", hex($1))/ge;
        return $str;
}

# Private function: create_mime_parser($msgdir)
# Create a MIME::Parser object and file into $msgdir
sub _create_mime_parser
{
        my ($self, $msgdir) = @_;
        my $parser = MIME::Parser->new();
        $parser->extract_nested_messages(1);
        $parser->extract_uuencode(1);
        $parser->output_to_core(0);
        $parser->tmp_to_core(0);
        my $filer = MIME::Parser::FileInto->new($msgdir);
        $filer->ignore_filename(1);
        $parser->filer($filer);
        return $parser;
}

# Private function: handle_scan($qid, $cwd)
# Handle the "scan" command from the multiplexor.
sub _handle_scan
{
        my ($self, $qid, $cwd) = @_;

        # Change to working directory
        if (!chdir($cwd)) {
                return $self->_reply_error("Could not chdir($cwd): $!");
        }

        # Read COMMANDS file
        $self->push_tag($qid, 'Reading COMMANDS');
        my $ctx = $self->read_commands_file(undef, 1);
        $self->pop_tag($qid);
        if (!$ctx) {
                return $self->_reply_error("Could not read COMMANDS file");
        }
        $ctx->in_message_context($self, 1);
        $ctx->cwd($cwd);

        # Create work directory for MIME::Parser;
        my $msgdir = './Work';
        if (!mkdir($msgdir, 0750)) {
                return $self->_reply_error("Could not mkdir($msgdir): $!");
        }

        # Parse the message
        my $parser = $self->_create_mime_parser($msgdir);
        my $filer = MIME::Parser::FileInto->new($msgdir);
        $filer->ignore_filename(1);
        $parser->filer($filer);

        my $msg_fh;
        if (!open($msg_fh, $self->inputmsg())) {
                $self->_signal_complete($ctx);
                return $self->_reply_error("Could not open " . $self->inputmsg() . ": $!");
        }
        $self->push_tag($qid, "Parsing Message");
        my $entity = $parser->parse($msg_fh);
        $self->pop_tag($qid);
        $msg_fh->close();

        if (!$entity) {
                $self->_signal_complete($ctx);
                return $self->_reply_error("Could not parse MIME in " . $self->inputmsg() . ": $!");
        }
        $ctx->mime_entity($entity);

        # Check for X-Mailmunge-Remailed header
        # indicating a streamed or otherwise remailed message
        my $data = $entity->head->get('X-Mailmunge-Remailed');
        if ($data) {
                if ($ctx->connecting_ip eq '127.0.0.1' || $ctx->connecting_ip eq '::1') {
                        chomp($data);
                        my ($ip, $qid, $bogus) = split(/\s+/, $data);
                        if ($ip && $qid && !$bogus) {
                                $self->log($ctx, 'info', "Resent from queue-ID: $qid; original IP: $ip");
                                $ctx->hostip($ip);
                                $ctx->hostname($self->ip_to_hostname($ip));
                                $ctx->was_resent(1);
                        }
                }

                # Delete the header before forwarding on!
                $self->action_delete_all_headers($ctx, 'X-Mailmunge-Remailed');
        }

        # Call filter_message
        $self->push_tag($qid, "In filter_message");
        $self->filter_message($ctx);
        $self->pop_tag($qid);

        # Write NEWBODY file if $ctx->new_mime_entity has
        # been called
        if ($ctx->new_mime_entity && !$ctx->message_rejected) {
                if (!$self->_replace_message($ctx)) {
                        # If _replace_message fails, it takes care of
                        # calling _signal_complete and _reply_error, so
                        # just return.
                        return;
                }
        }

        # Call filter_wrapup
        if (!$ctx->message_rejected) {
                $self->push_tag($qid, "In filter_wrapup");
                $ctx->in_filter_wrapup(1);
                $self->filter_wrapup($ctx);
                $self->pop_tag($qid);
                $ctx->in_filter_wrapup(0);
        }

        # Tell the Milter everything ran successfully
        $self->_signal_complete($ctx);
        $self->_reply_ok();
}

# Private function: _replace_message($ctx)
# Ask the MTA to replace the message body with the body of $ctx->mime_entity
sub _replace_message
{
        my ($self, $ctx) = @_;
        my $entity = $ctx->new_mime_entity;
        unless ($entity) {
                $self->_signal_complete($ctx);
                $self->_reply_error("No replacement entity for _replace_message()");
                return 0;
        }

        my $fh;
        if (!open($fh, '>' . $self->_newbody)) {
                $self->_signal_complete($ctx);
                $self->_reply_error("Could not open " . $self->_newbody . ": $!");
                return 0;
        }
        $self->push_tag($ctx, "Writing new body");
        $entity->print_body($fh);
        $self->pop_tag($ctx);
        if (!$fh->close()) {
                $self->_signal_complete($ctx);
                $self->_reply_error("Could not close " . $self->_newbody . ": $!");
                return 0;
        }

        # Update content type
        my $ct = $entity->head->get('Content-Type');
        if (!defined($ct)) {
                my $type = $entity->mime_type;
                my $boundary = $entity->head->multipart_boundary;
                if (defined($boundary)) {
                        $ct = "$type; boundary=\"$boundary\"";
                } else {
                        $ct = $type;
                }
        }
        if (defined($ct)) {
                $ct =~ s/\s+$//s;
                $ct =~ s/^\s+//s;
                chomp($ct);
                $self->_write_result_line($ctx, 'M', $ct);
        }

        # Fix up all the other MIME headers associated with the
        # replacement entity
        my ($new_headers, $old_headers);
        my $new_head = $entity->head;
        my $old_head = $ctx->mime_entity->head;
        foreach my $tag (grep {/^content-/i} ($new_head->tags)) {
                $new_headers->{lc($tag)} = [$tag, $new_head->get($tag)];
        }
        foreach my $tag (grep {/^content-/i} ($old_head->tags)) {
                $old_headers->{lc($tag)} = [$tag, $old_head->get($tag)];
        }

        # Add new or changed Content-* headers
        foreach my $tag (keys(%$new_headers)) {
                my ($hdr, $val) = @{$new_headers->{$tag}};
                next if (lc($tag) eq 'content-type');
                if (!exists($old_headers->{$tag})) {
                        chomp($val);
                        $self->action_change_header($ctx, $hdr, $val);
                        next;
                }
                if ($val ne $old_headers->{$tag}->[1]) {
                        chomp($val);
                        $self->action_change_header($ctx, $hdr, $val);
                }
        }

        # Remove dropped Content-* headers
        foreach my $tag (keys(%$old_headers)) {
                next if (lc($tag) eq 'content-type');
                if (!exists($new_headers->{$tag})) {
                        $self->action_delete_header($ctx, $old_headers->{$tag}->[0]);
                }
        }

        # Make sure it's MIME. :)
        if (!$new_head->get('MIME-Version')) {
                $self->action_change_header($ctx, 'MIME-Version', '1.0');
        }

        $self->_signal_changed($ctx);
        return 1;
}

=head2 rfc2822_date([$now])

Returns an RFC2822-formatted date for the Unix time $now (defaults to time()
if $now is nto supplied.)  An RFC2822-formatted date looks something like:

    Fri, 1 Jan 2021 15:49:21 -0500

=cut
sub rfc2822_date
{
        my ($self, $now) = @_;

        $now = time() unless defined($now);

	my ($ss, $mm, $hh, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($now);
	return sprintf("%s, %02d %s %04d %02d:%02d:%02d %s",
                       (qw( Sun Mon Tue Wed Thu Fri Sat ))[$wday],
                       $mday,
                       (qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec ))[$mon],
                       $year + 1900,
                       $hh,
                       $mm,
                       $ss,
                       header_timezone($now)
            );
}

my $cached_timezone;

=head2 header_timezone ()

Returns the appropriate value to use for this host's timezone in a
mail header.  Returns something of the form "+HHMM" or "-HHMM" depending
on your local time zone.

=cut
sub header_timezone
{
        return $cached_timezone if $cached_timezone;

        my($now) = @_;

        my($sec, $min, $hr, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($now);
        my $a = timelocal($sec, $min, $hr, $mday, $mon, $year);
        my $b = timegm($sec, $min, $hr, $mday, $mon, $year);
        my $c = ($b - $a) / 60;
        $hr = int(abs($c) / 60);
        $min = abs($c) - 60 * $hr;

        if ($c >= 0) {
                $cached_timezone = sprintf("+%02d%02d", $hr, $min);
        } else {
                $cached_timezone = sprintf("-%02d%02d", $hr, $min);
        }
        return $cached_timezone;
}

=head2 synthesize_received_header ($ctx)

Returns a Received: header similar to the one that I<would> be added
by the MTA if it delivered the message currently being processed.

Use this for message scanners such as SpamAssassin that expect to
find the most-recent MTA header at the beginning of the message.

=cut

sub synthesize_received_header
{
        my ($self, $ctx) = @_;

        my $hdr;
        my $hn = $ctx->sendmail_macro('if_name');
        my $auth = $ctx->sendmail_macro('auth_authen');

        $hn = $self->get_host_name() unless (defined($hn) and ($hn ne ""));

        if ($ctx->connecting_name ne '[' . $ctx->connecting_ip . ']') {
                $hdr = 'Received: from ' . $ctx->helo . ' (' . $ctx->connecting_name . ' [' . $ctx->connecting_ip . "])\n";
        } else {
                $hdr = 'Received: from ' . $ctx->helo . ' ([' . $ctx->connecting_ip . "])\n";
        }
        if ($auth) {
                $hdr .= "\tby $hn (envelope-sender " . $ctx->sender . ") (" . $self->product_name . ") with ESMTPA id " . $ctx->qid;
        } else {
                $hdr .= "\tby $hn (envelope-sender " . $ctx->sender . ") (" . $self->product_name . ") with ESMTP id " . $ctx->qid;
        }
        if (scalar(@{$ctx->recipients}) != 1) {
                $hdr .= '; ';
        } else {
                $hdr .= "\n\tfor " . $ctx->recipients->[0] . '; ';
        }
        $hdr .= $self->rfc2822_date() . "\n";

        return $hdr;
}

my $private_host_name;

=head2 get_host_name()

(Attempt to) get the host's fully-qualified name.  Returns the best
guess at the hostname.

=cut
sub get_host_name
{
        return $private_host_name if defined($private_host_name);

        $private_host_name = hostname();
        $private_host_name = 'localhost' unless defined($private_host_name);

        # Now make it FQDN
        my($fqdn) = gethostbyname($private_host_name);
        $private_host_name = $fqdn if (defined $fqdn) and length($fqdn) > length($private_host_name);

        return $private_host_name;
}

=head2 privdata($key [,$val)

Get or set private data.  The data's lifetime is the lifetime of the
filter process.  One use of this, for example, could be to connect
to a database and store the handle.  In initialize(), you could say:

    my $dbh = DBI->connect($connect_string, $username, $password);
    $self->privdata('dbh', $dbh);

and then in the remaining functions you could retrieve the database
handle:

    my $dbh = $self->privdata('dbh');

Using privdata ensures that you won't interfere with any built-in
state stored by the filter for internal purposes, and it is cleaner
than littering your code with global variables.

=cut
sub privdata
{
        my ($self, $key, $val) = @_;
        if (defined($val)) {
                $self->{privdata}->{$key} = $val;
        }
        return $self->{privdata}->{$key};
}

1;

__END__

=head1 SEE ALSO

L<Mailmunge::Filter::Compat>, L<Mailmunge::Context>, L<Mailmunge::Response>, L<Mailmunge>

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
