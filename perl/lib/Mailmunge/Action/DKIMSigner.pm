package Mailmunge::Action::DKIMSigner;
use strict;
use warnings;

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
                $file = 'HEADERS';
        } else {
                $fh = IO::File->new("$wd/INPUTMSG", O_RDONLY);
        }

        return undef unless $fh;

        while(<$fh>) {
                # Replace local line terminators with SMTP line terminators
                chomp;
                s/\015$//;
                $signer->PRINT("$_\015\012");
        }
        $fh->close();
        if ($file eq 'HEADERS') {
                $fh = IO::File->new($wd . '/' . $filter->_newbody(), O_RDONLY);
                return undef unless $fh;
                while(<$fh>) {
                        chomp;
                        s/\015$//;
                        $signer->PRINT("$_\015\012");
                }
                $fh->close();
        }

        my $sig = $signer->signature()->as_string();
	$sig =~ s/^DKIM-Signature:\s+//i;
	return $ctx->action_add_header('DKIM-Signature', $sig);
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
            Selecter  => 'my_selector',
            Key       => Mail::DKIM::PrivateKey->load(Data => get_my_key()));

        my $action = Mailmunge::Action::DKIMSigner->new($self);
        $action->add_dkim_signature($ctx, $signer);
    }

=head1 METHODS

=head2 add_dkim_signature($ctx, $signer)

Given a Mail::DKIM::Signer instance (that the caller must create with
appropriate settings), this method adds a DKIM-Signature: header to
the current message.  It should be called from filter_wrapup.
