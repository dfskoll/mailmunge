use strict;
use warnings;
package Mailmunge::Test::SpamAssassin;
use base qw(Mailmunge::Test);

use Mailmunge::Constants;
use Mail::SpamAssassin;

my $sa_spam_tester;

sub _spam_assassin_init
{
        my ($self, $local_tests_only, $config) = @_;
        return $sa_spam_tester if $sa_spam_tester;

        # Look for default config files if we are not passed one
        if (!defined($config)) {
                my $cdir = Mailmunge::Constants->get('Path:CONFDIR');
                foreach my $dir ($cdir, '/etc/mail') {
                        foreach my $f ('sa-mailmunge.cf',
                                       'spamassassin/sa-mailmunge.cf',
                                       'spamassassin/local.cf',
                                       'spamassassin.cf') {
                                if (-r "$cdir/$f") {
                                        $config = "$cdir/$f";
                                        last;
                                }
                        }
                }
        }
        my $sa_args = {
                local_tests_only   => $local_tests_only,
                dont_copy_prefs    => 1,
                userprefs_filename => $config,
                user_dir           => Mailmunge::Constants->get('Path:QUARANTINEDIR')
        };
	if ($Mail::SpamAssassin::VERSION < 3.001005) {
		$sa_args->{LOCAL_STATE_DIR} = '/var/lib';
		$sa_args->{LOCAL_RULES_DIR} = '/etc/mail/spamassassin';
	}
        $sa_spam_tester = Mail::SpamAssassin->new( $sa_args );
        return $sa_spam_tester;
}

sub spam_assassin_status
{

        my ($self, $ctx, $local_tests_only, $config) = @_;
        my $filter = $self->filter;
        my $tester = $self->_spam_assassin_init($local_tests_only, $config);
        return undef unless $tester;

        my $mail = $self->_spam_assassin_mail($ctx, $tester);
        return undef unless $mail;

        my $status;
        $filter->push_tag($ctx, 'Running SpamAssassin');
        $status = $tester->check($mail);
        $mail->finish();
        $filter->pop_tag($ctx);
        return $status;
}

sub _spam_assassin_mail
{
        my ($self, $ctx, $sa) = @_;

        my $filter = $self->filter;

        my $fh;
        return undef unless open($fh, '<' . $filter->inputmsg);

        my @msg = <$fh>;
        close($fh);
        # Synthesize a "Return-Path" and "Received:" header
        my @sahdrs;
        push (@sahdrs, 'Return-Path: ' . $ctx->sender . "\n");
        push (@sahdrs, split(/^/m, $filter->synthesize_received_header($ctx)));

        unshift(@msg, @sahdrs);

        return $sa->parse(\@msg);
}

1;

__END__

=head1 NAME

Mailmunge::Test::SpamAssassin - run SpamAssassin against the current
message.

=head1 ABSTRACT

This class runs SpamAssassin against the message and returns the
SpamAssassin C<Mail::SpamAssassin::PerMsgStatus> object that is
the result of the SpamAssassin run.

You must have C<Mail::SpamAssassin> installed to use this class.

=head1 SYNOPSIS

    package MyFilter;
    use Mailmunge::Test::SpamAssassin;

    sub filter_begin {
        my ($self, $ctx) = @_;
        my $test = Mailmunge::Test::SpamAssassin->new($self);
        my $status = $test->spam_assassin_status($ctx);
        if ($status) {
            if ($status->get_score() >= 5) {
                $self->action_change_header($ctx, 'Subject', '[SPAM] ' . $ctx->subject);
            }
            $status->finish();
        }

        # ... rest of filter_begin
    }

=head1 CLASS METHODS

=head2 Mailmunge::Test::SpamAssassin->new($filter)

Constructs a new Mailmunge::Test::SpamAssassin object and stores a copy
of $filter in it.

=head1 INSTANCE METHODS

=head2 spam_assassin_status($ctx, $local_tests_only, $config)

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
