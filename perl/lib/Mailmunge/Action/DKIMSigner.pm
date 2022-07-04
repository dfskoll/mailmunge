package Mailmunge::Action::DKIMSigner;
use strict;
use warnings;

use base qw(Mailmunge::Action);

use IO::File;

sub add_dkim_signature
{
        my ($self, $ctx, $signer) = @_;

        my $wd = $ctx->cwd;

        my $fh;

        my $file = 'INPUTMSG';

        my $filter = $self->filter;

        # If message has been altered, sign the altered message;
        # otherwise; sign original
        if (-f $wd . '/' . $filter->_newbody()) {
                $fh = IO::File->new($wd . '/' . $filter->headers_file(), O_RDONLY);
                $file = 'PRISTINE_HEADERS';
        } else {
                $fh = IO::File->new("$wd/INPUTMSG", O_RDONLY);
        }

        return undef unless $fh;
        $self->_consume($signer, $fh);
        if ($file eq 'PRISTINE_HEADERS') {
                # Add blank line between headers and body
                $signer->PRINT("\015\012");
                $fh = IO::File->new($wd . '/' . $filter->_newbody(), O_RDONLY);
                return undef unless $fh;
                $self->_consume($signer, $fh);
        }

        $signer->CLOSE();
        my $sig = $signer->signature()->as_string();
	$sig =~ s/^DKIM-Signature:\s+//i;
	return $ctx->action_add_header('DKIM-Signature', $sig);
}

sub _consume
{
        my ($self, $signer, $fh) = @_;
        while(<$fh>) {
                chomp;
                s/\015$//;
                $signer->PRINT("$_\015\012");
        }
        $fh->close();
}

1;

__END__

=head1 NAME

Mailmunge::Action::DKIMSigner - Add a DKIM-Signature: header to a message

=head1 ABSTRACT

This class implements a method that adds a DKIM signature to a message.

=head1 SYNOPSIS

    package MyFilter;
    use base qw(Mailmunge::Filter);
    use Mail::DKIM::Signer;
    use Mail::DKIM::TextWrap;
    use Mailmunge::Action::DKIMSigner;

    sub filter_wrapup {
        my ($self, $ctx) = @_;
        my $signer = Mail::DKIM::Signer->new(
            Algorithm => 'rsa-sha256',
            Method    => 'relaxed',
            Domain    => 'example.org',
            Selector  => 'my_selector',
            Key       => Mail::DKIM::PrivateKey->load(Data => get_my_key()));

        my $action = Mailmunge::Action::DKIMSigner->new($self);
        $action->add_dkim_signature($ctx, $signer);
    }

=head1 METHODS

=head2 add_dkim_signature($ctx, $signer)

Given a Mail::DKIM::Signer instance (that the caller must create with
appropriate settings), this method adds a DKIM-Signature: header to
the current message.  It should be called from filter_wrapup.

=head1 INBOUND vs OUTBOUND MAIL

Generally, we only want to sign outbound mail, so the question becomes:
How do we distinguish "outbound" from "inbound" mail?  There's no easy
answer to this because it's really a policy decision.  There are three
types of email:

=over 4

=item Inbound mail

Mail that originates from an external machine and
is destined for either the local host or a downstream SMTP server that
we control.

=item Outbound mail

Mail that originates from the local host or an
internal machine that we control and is destined for an SMTP server
that we do not control.

=item Local mail

Mail that both originates on and is destined for the
localhost or a machine that we control.

=back

One clear sign of outbound mail is mail sent from an authenticated
session.  You can detect this by looking at
C<$ctx-E<gt>mta_macro('auth_authen')>; if this is defined and
non-blank, then the SMTP session is authenticated.

Otherwise, you can obtain the connecting SMTP client address from
C<$ctx-E<gt>connecting_ip>, and for each recipient, you can examine
the destination mailer with C<$ctx-E<gt>get_recipient_mailer($rcpt)>.
These should give you enough information to determine if the
originating machine and destination machine(s) are local or off-site.

=head1 WARNING

C<Mailmunge::Action::DKIMSigner> can correctly sign a message that has
not been modified, or whose message body has been replaced without
altering the MIME type.  However, if certain headers such as
C<Content-Type>, C<Subject> or C<From> are altered, the signature will
be I<incorrect>.  The reason is that header changes are made only once
the Perl code has finished running and the C milter library functions
are invoked; as such, the DKIM-signing code will not see the modified
headers.  If you are going to sign an outbound message, you should
I<not> make any changes to headers that might cause the signature to
fail.  Adding C<X-*> headers is OK since these are not part of the
DKIM signature.
