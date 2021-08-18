use strict;
use warnings;

# All of these utility functions are in the main package!

use Mailmunge::Context;
use Cwd;
use File::Spec;
use MIME::Parser;
use IO::File;
use Test::Mailmunge::Filter;

sub make_test_context
{
        return Mailmunge::Context->new(recipients => ['good@example.com'],
                                sender     => 'test@example.com',
                                hostip     => '192.168.1.1',
                                hostname   => 'server.example.com',
                                connecting_ip     => '192.168.1.1',
                                connecting_name   => 'server.example.com',
                                first_recip => 'good@example.com',
                                helo       => 'server.example.com',
                                cwd        => '.',
                                qid        => 'queue-id-here',
            );
}

sub start_multiplexor
{
        my ($dir, $filter) = @_;
        $dir = File::Spec->rel2abs($dir);
        $filter = File::Spec->rel2abs($filter);
        $ENV{TESTDIR} = getcwd;
        my $prog;
        if (-x '../c/mailmunge-multiplexor') {
                $prog = '../c/mailmunge-multiplexor';
        } else {
                $prog = 'mailmunge-multiplexor';
        }
        system($prog, '-l', '-Z', '-z', $dir, '-s', "$dir/mx.sock", '-f', $filter, '-p', "$dir/mx.pid", '-Y', 'mm-mx-test-instance');
}

sub stop_multiplexor
{
        my ($dir) = @_;
        my $pid = `cat $dir/mx.pid 2>/dev/null`;
        chomp($pid);
        if ($pid =~ /^\d+$/) {
                kill 'TERM', $pid;
        }
}

sub mm_mx_ctrl
{
        my $dir = shift;
        my $fh;
        my $prog;
        if (-x '../c/mm-mx-ctrl') {
                $prog = '../c/mm-mx-ctrl';
        } else {
                $prog = 'mm-mx-ctrl';
        }
        if (!open($fh, '-|', $prog, '-s', "$dir/mx.sock", @_)) {
                return '';
        }
        my $ans = <$fh>;
        chomp($ans);
        close($fh);
        return $ans;
}

sub results_has_lines
{
        my $dir = shift;

        my $num = scalar(@_);
        my $num_seen = 0;

        my $fh;
        return 0 unless (open($fh, '<', "$dir/RESULTS"));

        while(<$fh>) {
                chomp;
                my $line = $_;
                foreach my $wanted (@_) {
                        if ($line eq $wanted) {
                                $num_seen++;
                                last if $num_seen == $num;
                        }
                }
        }
        $fh->close();
        return ($num_seen == $num);
}

# Given a $ctx, create a COMMANDS file.
# This is the inverse of Mailmunge::Context->read_command_filehandle
sub write_commands_file
{
        my ($dir, $ctx) = @_;
        my $fh;
        if (!open($fh, ">$dir/COMMANDS")) {
                die("Could not write $dir/COMMANDS: $!");
        }
        my $filter = Test::Mailmunge::Filter->new();
        $fh->print('S' . $filter->_percent_encode($ctx->sender) . "\n") if $ctx->sender;
        $fh->print("!\n") if $ctx->suspicious_chars_in_headers;
        $fh->print("?\n") if $ctx->suspicious_chars_in_body;
        $fh->print('I' . $filter->_percent_encode($ctx->connecting_ip) . "\n") if $ctx->connecting_ip;
        $fh->print('H' . $filter->_percent_encode($ctx->connecting_name) . "\n") if $ctx->connecting_name;
        $fh->print('Q' . $filter->_percent_encode($ctx->qid) . "\n") if $ctx->qid;
        $fh->print('X' . $filter->_percent_encode($ctx->message_id) . "\n") if $ctx->message_id;
        $fh->print('E' . $filter->_percent_encode($ctx->helo) . "\n") if $ctx->helo;
        $fh->print('i' . $filter->_percent_encode($ctx->mailmunge_id) . "\n") if $ctx->mailmunge_id;
        $fh->print('U' . $filter->_percent_encode($ctx->subject) . "\n") if $ctx->subject;

        foreach my $m (keys(%{$ctx->{sendmail_macros}})) {
                $fh->print('=' . $filter->_percent_encode($m) . ' ' . $filter->_percent_encode($ctx->sendmail_macro($m)) . "\n");
        }
        foreach my $r (@{$ctx->recipients || []}) {
                my ($mailer, $host, $addr) = @{$ctx->get_recipient_mailer($r) || []};
                $fh->print('R' . $filter->_percent_encode($r) . ' ' . $filter->_percent_encode($mailer, '?') . ' ' . $filter->_percent_encode($host, '?') . ' ' . $filter->_percent_encode($addr, '?') . "\n");
                if ($ctx->recipient_esmtp_args && $ctx->recipient_esmtp_args->{$r}) {
                        foreach my $arg (@{$ctx->recipient_esmtp_args->{$r}}) {
                                $fh->print('r' . $filter->_percent_encode($arg) . "\n");
                        }
                }
        }
        if ($ctx->was_resent) {
                $fh->print('J' . $filter->_percent_encode($ctx->hostip) . "\n");
        }

        # Indicate that we're done.
        $fh->print("F\n");
        $fh->close();
}

sub set_context_fields_from_msg
{
        my ($ctx, $entity) = @_;
        my $head = $entity->head;
        return unless $head;

        $ctx->mime_entity($entity);
        if ($entity->get('Return-Path')) {
                my $x = $entity->get('Return-Path');
                chomp($x);
                $ctx->sender($x);
        }
        if ($entity->get('Subject')) {
                my $x = $entity->get('Subject');
                chomp($x);
                $ctx->subject($x);
        }
        if ($entity->get('Message-ID')) {
                my $x = $entity->get('Message-Id');
                chomp($x);
                $ctx->message_id($x);
        }
        return $ctx;
}

# Return a Mailmunge::Context object with
# mime_entity and a few other fields set.
sub parse_and_copy_msg
{
        my ($output_dir, $msg, $new_subject) = @_;
        my $parser = MIME::Parser->new;
        $parser->output_to_core(1);
        if ($new_subject) {
                system("sed -e 's/__SUBJECT__/$new_subject/' < $msg > $output_dir/INPUTMSG");
        } else {
                system('cp', $msg, "$output_dir/INPUTMSG");
        }

        my $entity = $parser->parse(IO::File->new("$output_dir/INPUTMSG"));
        # Generate HEADERS
        my $head = $entity->head;
        $head->unfold;
        if (open(OUT, ">$output_dir/HEADERS")) {
                print OUT $head->as_string;
                close(OUT);
        }
        my $ctx = Mailmunge::Context->new();
        return set_context_fields_from_msg($ctx, $entity);
}

1;

__END__

=head1 NAME

Test::Mailmunge::Utils - utility functions for Mailmunge unit tests

=head1 ABSTRACT

Test::Mailmunge::Utils defines a number of utility functions I<in the main package>
that are useful for unit tests.

=head1 SYNOPSIS

    use Test::Mailmunge::Utils;
    my $ctx = make_test_context();

=head1 FUNCTIONS

Note that the functions will be documented very briefly.  Since they
are of use to people writing unit tests, you should examine the source
code for more details.

=head2 make_test_context()

Returns a C<Mailmunge::Context> object useful for tests.

=head2 start_multiplexor($dir, $filter)

Starts C<mailmunge-multiplexor> with the spool directory
set to C<$dir> and the filter file set to C<$filter>.
Note that this will I<fail> if you are running as root,
so don't do that.

Sets the socket to C<$dir/mx.sock>

=head2 stop_multiplexor($dir)

Stops the instance of C<mailmunge-multiplexor> that was
started by C<start_multiplexor($dir, $filter)>.

=head2 mm_mx_ctrl($cmd, $arg1, $arg2...)

Runs C<mm_mx_ctrl> with the specified command and arguments.
On success, returns the output of C<mm-mx-ctrl>.  On failure,
returns the empty string.

=head2 write_commands_file($dir, $ctx)

Writes a COMMANDS file in C<$dir> that (when read by
the running filter) will recreate C<$ctx>.

=head2 set_context_fields_from_msg($ctx, $entity)

Given a MIME::Entity C<$entity>, sets the fields
C<sender>, C<subject> and C<message_id> on C<$ctx>
based on C<$entity>.

=head2 parse_and_copy_msg($output_dir, $input_msg)

Given a file C<$input_msg> containing an RFC5322
mail message, copy the file to C<"$output_dir/INPUTMSG">
and parse it.  Return the MIME::Entity resulting from
parsing the message,

This method also creates a HEADERS file in C<$output_dir>.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.

