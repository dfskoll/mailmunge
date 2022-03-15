package Mailmunge::Action::Boilerplate;
use strict;
use warnings;

use HTML::Parser;

use base qw(Mailmunge::Action);
use Mailmunge::Constants;

sub add_text_boilerplate
{
        my ($self, $ctx, $toplevel, $boilerplate, $at_start, $all) = @_;
        if ($self->_add_boilerplate($ctx, $toplevel, $boilerplate, $at_start, $all, 'text/plain')) {
                $ctx->new_mime_entity($toplevel);
                return 1;
        }
        return 0;
}

sub add_html_boilerplate
{
        my ($self, $ctx, $toplevel, $boilerplate, $at_start, $all) = @_;
        if ($self->_add_boilerplate($ctx, $toplevel, $boilerplate, $at_start, $all, 'text/html')) {
                $ctx->new_mime_entity($toplevel);
                return 1;
        }
        return 0;
}

sub _add_boilerplate
{
        my ($self, $ctx, $entity, $boilerplate, $at_start, $all, $mime_type) = @_;

        if ($entity->parts) {
                my $did_something = 0;
                foreach my $part ($entity->parts) {
                        $did_something = 1 if ($self->_add_boilerplate($ctx, $part, $boilerplate, $at_start, $all, $mime_type));
                        return 1 if $did_something && !$all;
                }
                return $did_something;
        }

        my $errmsg = $self->_add_to_part($ctx, $entity, $boilerplate, $at_start, $mime_type);
        return 1 if (defined($errmsg) && ($errmsg eq 'OK'));

        if (defined($errmsg)) {
                $self->filter->log($ctx, 'warning', "Could not add boilerplate to MIME part: $errmsg");
        }
        return 0;
}

sub _add_to_part
{
        my ($self, $ctx, $part, $boilerplate, $at_start, $mime_type) = @_;

        return undef unless (lc($part->mime_type) eq $mime_type);

        if ($mime_type eq 'text/plain') {
                return $self->_add_to_text_part($ctx, $part, $boilerplate, $at_start);
        } elsif ($mime_type eq 'text/html') {
                return $self->_add_to_html_part($ctx, $part, $boilerplate, $at_start);
        }
        return undef;
}

sub _html_echo
{
        my ($p, $text) = @_;
        $p->{mm}->{ofh}->print($text);
}

sub _html_end
{
        my ($p, $tagname, $text) = @_;

        if (!$p->{mm}->{added}) {
                if ($tagname eq 'body' || $tagname eq 'html') {
                        $p->{mm}->{ofh}->print($p->{mm}->{txt});
                        $p->{mm}->{added} = 1;
                }
        }
        $p->{mm}->{ofh}->print($text);

}

sub _html_start
{
        my ($p, $tagname, $text) = @_;
        if (!$p->{mm}->{added}) {
                # Also look for other tags in case of malformed
                # HTML that doesn't have proper body tags
                if ($tagname eq 'body' ||
                    $tagname eq 'p'    ||
                    $tagname eq 'div'  ||
                    $tagname eq 'a') {
                        if ($tagname ne 'body') {
                                $p->{mm}->{ofh}->print($p->{mm}->{txt});
                        }
                        $p->{mm}->{ofh}->print($text);
                        if ($tagname eq 'body') {
                                $p->{mm}->{ofh}->print($p->{mm}->{txt});
                        }
                        $p->{mm}->{added} = 1;
                        return;
                }
        }
        $p->{mm}->{ofh}->print($text);
}

sub _add_to_html_part
{
        my ($self, $ctx, $part, $boilerplate, $at_start) = @_;
        # Add terminating newline to boilerplate if it lacks one
        $boilerplate .= "\n" unless substr($boilerplate, -1, 1) eq "\n";

        my $body = $part->bodyhandle;
        return 'MIME::Entity->bodyhandle returned undef' unless $body;

        my $path = $body->path();
        return 'MIME::Body has no path... is it stored on disk?' unless $path;

        my $new = $path . '.tmp';

        my $ifh = $body->open('r');
        return "body->open() failed: $!" unless $ifh;

        my $ofh;
        if (!open($ofh, '>', $new)) {
                my $err = $!;
                $ifh->close();
                return "Cannot write $new: $err";
        }

        my $p;
        if ($at_start) {
                $p = HTML::Parser->new(api_version => 3,
                                       default_h => [\&_html_echo,  'self,text'],
                                       start_h   => [\&_html_start, 'self,tagname,text']);
        } else {
                $p = HTML::Parser->new(api_version => 3,
                                       default_h => [\&_html_echo,  'self,text'],
                                       end_h     => [\&_html_end,   'self,tagname,text']);
        }

        # State to store across HTML::Parser callbacks
        $p->{mm} = {ifh   => $ifh,
                    ofh   => $ofh,
                    added => 0,
                    txt   => $boilerplate};
        $p->unbroken_text(1);
        $p->parse_file($ifh);

        # If it's at the end and wasn't added, add it now
        if (!$at_start && !$p->{mm}->{added}) {
                $ofh->print($boilerplate);
                $p->{mm}->{added} = 1;
        }

        $ifh->close();
        $ofh->close();

        if (!$p->{mm}->{added}) {
                unlink($new);
                return undef;
        }
        if (rename($new, $path)) {
                return 'OK';
        }
        my $err = $!;
        unlink($new);
        return "Cannot rename($new, $path): $!";

}

sub _add_to_text_part
{
        my ($self, $ctx, $part, $boilerplate, $at_start) = @_;

        # Add terminating newline to boilerplate if it lacks one
        $boilerplate .= "\n" unless substr($boilerplate, -1, 1) eq "\n";

        my $body = $part->bodyhandle;
        return 'MIME::Entity->bodyhandle returned undef' unless $body;

        my $path = $body->path();
        return 'MIME::Body has no path... is it stored on disk?' unless $path;

        my $new = $path . '.tmp';

        my $ifh = $body->open('r');
        return "body->open() failed: $!" unless $ifh;

        my $ofh;
        if (!open($ofh, '>', $new)) {
                my $err = $!;
                $ifh->close();
                return "Cannot write $new: $err";
        }
        if ($at_start) {
                $ofh->print($boilerplate);
        }
        my $l;
        while (defined($l = $ifh->getline())) {
                $ofh->print($l);
        }
        if (!$at_start) {
                $ofh->print($boilerplate);
        }
        $ofh->close();
        $ifh->close();
        if (!rename($new, $path)) {
                my $err = $!;
                unlink($new);
                return "Cannot rename($new, $path): $!";
        }
        return 'OK';
}

1;

__END__

=head1 NAME

Mailmunge::Action::Boilerplate - Add boilerplate to text parts of a message

=head1 ABSTRACT

This class implements methods that let you add boilerplate text to
the beginning or end of text/plain or text/html parts.

=head1 SYNOPSIS

    package MyFilter;
    use base qw(Mailmunge::Filter);
    use Mailmunge::Action::Boilerplate;

    sub filter_message {
        my ($self, $ctx) = @_;
        my $action = Mailmunge::Action::Boilerplate->new($self);

        $action->add_text_boilerplate($ctx, $ctx->mime_entity,
                                      "\nAnnoying plain-text boilerplate\n");
        $action->add_html_boilerplate($ctx, $ctx->mime_entity,
                                      "\n<p><b>Really</b> annoying HTML boilerplate</p>\n");
    }

    my $filter = MyFilter->new();
    $filter->run();

    1;

=head1 METHODS

=head2 Mailmunge::Action::Boilerplate-E<gt>new($filter);

Constructor.  Typically used within a filter file as follows:

        my $action = Mailmunge::Action::Boilerplate->new($self);


=head2 add_text_boilerplate($ctx, $entity, $text, $at_start, $all)

C<$entity> must be the top-level MIME entity; typically, you
would pass C<$ctx-E<gt>entity> as the C<$entity> argument.

C<$text> is plain-text boilerplate.

If C<$at_start> is true, then the boilerplate is added
at the beginning of the text/plain part(s).  If false
or omitted, the boilerplate is added at the end.

If C<$all> is true, then the boilerplate is added
to I<all> text/plain parts in the message.  If
false or omitted, the boilerplate is added only to
the I<first> text/plain part.

Note that you may need to include newlines liberally
in C<$text> for best results.

=head2 add_html_boilerplate($ctx, $entity, $html, $at_start, $all)

C<$entity> must be the top-level MIME entity; typically, you
would pass C<$ctx-E<gt>entity> as the C<$entity> argument.

C<$html> is plain-text boilerplate.

C<$at_start> and C<$all> have the same meanings as
in C<add_text_boilerplate>, but they apply to
text/html parts rather than text/plain parts.

This function adds C<$html> boilerplate to the start or
end of one or all of the C<text/html> parts in the message,
depending on the values of C<$at_start> and C<$all>.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
