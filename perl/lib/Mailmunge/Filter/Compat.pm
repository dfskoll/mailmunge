use strict;
use warnings;

package Mailmunge::Filter::Compat;

use base qw(Mailmunge::Filter);

use MIME::Words qw(:all);
use Encode;

sub _data
{
        my ($self, $ctx) = @_;
        return $ctx->privdata('compat_filter');
}

sub filter_message
{
        my ($self, $ctx) = @_;

        my $rebuilt;
        my $entity = $ctx->mime_entity;

        $ctx->privdata('compat_filter',
                       {changed => 0,
                        added_parts => [],
                        warnings => []});

        $self->push_tag($ctx, 'In filter_begin');
        $self->filter_begin($ctx);
        $self->pop_tag($ctx);

        if (!$ctx->message_rejected) {
                # We just want to dup the header into $rebuilt,
                # so temporarily reset parts to empty
                my @parts = $entity->parts;
                $entity->parts([]);
                $rebuilt = $entity->dup;
                $entity->parts(\@parts);

                # Rebuild the message
                $self->push_tag($ctx, 'In rebuild loop');
                map { $self->_rebuild_entity($ctx, $rebuilt, $_) } $entity->parts;
                $self->pop_tag($ctx);
                $ctx->mime_entity($rebuilt);
        }

        if (!$ctx->message_rejected) {
                $self->push_tag($ctx, 'In filter_end');
                $self->filter_end($ctx);
                $self->pop_tag($ctx);
        }

        # If changes were made, update the MIME entity
        if (!$ctx->message_rejected && $self->_data($ctx)->{changed}) {
                # Handle any added parts
                $self->_do_add_parts($ctx, $rebuilt);

                # Traverse down to the simplest part to eliminate
                # single-part "multipart" entities.
                while ($rebuilt->is_multipart) {
                        my @parts = $rebuilt->parts;
                        if (scalar(@parts) == 1) {
                                $rebuilt = $parts[0];
                        } else {
                                last;
                        }
                }
                $ctx->new_mime_entity($rebuilt);
        }
}

sub _do_add_parts {
        my ($self, $ctx, $rebuilt) = @_;

        $rebuilt->make_multipart;

        foreach my $part (@{$self->_data($ctx)->{added_parts} || [] }) {
                my ($entity, $offset) = @{$part};
                $rebuilt->add_part($entity, $offset);
        }

        # Add any warnings
        if (scalar(@{$self->_data($ctx)->{warnings} || []})) {
                my $wpart = MIME::Entity->build(Top => 0,
                                                Type => 'text/plain',
                                                Encoding => '-suggest',
                                                Disposition => 'inline',
                                                Charset => 'utf-8',
                                                Filename => 'warnings.txt',
                                                'X-Mailer' => undef,
                                                Data => [ map { encode('UTF-8', "$_\n", Encode::FB_PERLQQ) } (@{$self->_data($ctx)->{warnings}}) ]);
                $rebuilt->add_part($wpart);
        }
}

sub filter_begin     { return; }
sub filter_multipart { return; }
sub filter           { return; }
sub filter_end       { return; }
sub action_accept    { return; }

sub _rebuild_entity
{
        my ($self, $ctx, $out, $in) = @_;

        # Bail out early if we're rejecting
        return if $ctx->message_rejected();

        my @parts = $in->parts;
        my $type  = lc($in->mime_type);
        my $body  = $in->bodyhandle;
        my $fname = $self->take_stab_at_filename($in);
        $fname = '' unless defined($fname);
        my $extension = '';
        $extension = $1 if $fname =~ /(\.[^.]*)$/;

        # If no Content-Type: header, add one
        if (!$in->head->mime_attr('content-type')) {
                $in->head->mime_attr('Content-Type', $type);
        }

        $self->_data($ctx)->{action} = 'accept';
        if (!defined($body)) {
                $self->push_tag($ctx, 'In filter_multipart routine');
                $self->filter_multipart($ctx, $in, $fname, $extension, $type);
                $self->pop_tag($ctx);
                # Bail out if we're rejecting
                return if $ctx->message_rejected();

                if ($self->_data($ctx)->{action} eq 'drop') {
                        $self->_data($ctx)->{changed} = 1;
                        return 0;
                }
                if ($self->_data($ctx)->{action} eq 'replace') {
                        $self->_data($ctx)->{changed} = 1;
                        $out->add_part($self->_data($ctx)->{replacement_entity});
                        return 0;
                }

                my $subentity = $in->dup;
                $subentity->parts([]);
                $out->add_part($subentity);
                map { $self->_rebuild_entity($ctx, $subentity, $_) } @parts;
        } else {
                $self->push_tag($ctx, 'In filter routine');
                $self->filter($ctx, $in, $fname, $extension, $type);
                $self->pop_tag($ctx);

                # Bail out if we're rejecting
                return if $ctx->message_rejected();

                # If action is 'drop', just drop it silently;
                if ($self->_data($ctx)->{action} eq 'drop') {
                        $self->_data($ctx)->{changed} = 1;
                        return 0;
                }

                # If action is 'replace',
                # replace it with $self->_data($ctx)->{replacement_entity};
                if ($self->_data($ctx)->{action} eq 'replace') {
                        $self->_data($ctx)->{changed} = 1;
                        $out->add_part($self->_data($ctx)->{replacement_entity});
                        return 0;
                }

                # Otherwise, accept it
                $out->add_part($in);
        }
}

sub action_drop
{
        my ($self, $ctx) = @_;
        return unless $ctx->in_message_context($self);

        $self->_data($ctx)->{action} = 'drop';
}

sub action_drop_with_warning
{
        my ($self, $ctx, $warning) = @_;
        return unless $ctx->in_message_context($self);

        push(@{$self->_data($ctx)->{warnings}}, $warning);
        $self->_data($ctx)->{action} = 'drop';
}

sub action_accept_with_warning
{
        my ($self, $ctx, $warning) = @_;
        return unless $ctx->in_message_context($self);

        $self->_data($ctx)->{changed} = 1;
        push(@{$self->_data($ctx)->{warnings}}, $warning);
}

sub action_replace_with_warning
{
        my ($self, $ctx, $warning) = @_;
        return unless $ctx->in_message_context($self);

        $self->_data($ctx)->{action} = 'replace';
        $self->_data($ctx)->{replacement_entity} =
            MIME::Entity->build(Top => 0,
                                Type => 'text/plain',
                                Encoding => '-suggest',
                                Charset => 'utf-8',
                                Disposition => 'inline',
                                'X-Mailer' => undef,
                                Data => [ encode('UTF-8', "$warning\n", Encode::FB_PERLQQ) ]);
}

sub action_add_entity
{
        my ($self, $ctx, $entity, $offset) = @_;
        return unless $ctx->in_message_context($self);
        return if $ctx->in_filter_wrapup();
        $offset = -1 unless defined($offset);

        $self->_data($ctx)->{changed} = 1;
        push(@{$self->_data($ctx)->{added_parts}}, [$entity, $offset]);
}

sub action_add_part
{
        my ($self, $ctx, $type, $encoding, $data, $fname, $disposition, $offset) = @_;

        my $entity = MIME::Entity->build(Type => $type,
                                         Top => 0,
                                         'X-Mailer' => undef,
                                         Encoding => $encoding,
                                         Data => [$data]);
        $entity->head->mime_attr('Content-Disposition' => $disposition) if defined($disposition);
        $entity->head->mime_attr('Content-Disposition.filename' => $fname) if defined($fname);
        $entity->head->mime_attr('Content-Type.name' => $fname) if defined($fname);
        $self->action_add_entity($ctx, $entity, $offset);
}

sub take_stab_at_filename
{
        my ($self, $entity) = @_;
	my $guess = $entity->head->recommended_filename();

        return scalar( decode_mimewords( $guess ) ) if defined($guess);
	return '';
}

1;

__END__

=head1 NAME

Mailmunge::Filter::Compat - base class for Mailmunge filtering that includes
some backward-compatibility for migrating MIMEDefang filter code.

=head1 SYNOPSIS

C<Mailmunge::Filter::Compat> is a subclass of C<Mailmunge::Filter>.  As
such, all methods documented in L<Mailmunge::Filter> are also
available here.

C<Mailmunge::Filter::Compat> implements a C<filter_message> function that
in turn calls C<filter_begin>, C<filter>, C<filter_multipart>,
C<filter_end> and C<filter_wrapup> methods.  These methods operate
similarly to their counterparts in MIMEDefang filtering code and make
it easier to migrate MIMEDefang filters to Mailmunge.

If you derive your filter from C<Mailmunge::Filter::Compat>, you
I<must not> override C<filter_message>.  Instead, override
C<filter_begin>, C<filter>, C<filter_multipart>, C<filter_end> and
C<filter_wrapup> as required.

Any functions that are callable from C<filter_message> as well as
L<Mailmunge::Context> methods available to C<filter_message> are available
in C<filter_begin>, C<filter>, C<flter_multipart> and C<filter_end>.

The body filtering functions are called as follows:

=over 4

=item 1

C<filter_begin> is called once.

=item 2

Recursing through the MIME::Entity object C<$ctx-E<gt>mime_entity>,
C<filter_multipart> is called for each multipart/* sub-part and
C<filter> is called for each non-multipart sub-part.

=item 3

C<filter_end> is called once.  This is the last point at which you
are allowed to modify the message body.

=item 4

C<filter_wrapup> is called once.  In C<filter_wrapup>, modifications
to the message body are not allowed, but you are allowed to modify
top-level headers.  Typically, this is where you would do DKIM-signing.

=back

Note that if any method rejects a message by calling
C<action_bounce>, C<action_discard> or C<action_tempfail>, then filtering
is I<short-circuited> and remaining callbacks are I<not> called.

=head1 ABSTRACT

    package MyFilter;
    use base qw(Mailmunge::Filter::Compat);
    sub filter_begin {
        my ($self, $ctx) = @_;
        # ... etc
    }

=head1 METHODS

=head2 filter_message($ctx)

Overrides C<filter_message> from the base C<Mailmunge::Filter> class.
I<Do not tamper with or override this method.>

The $ctx fields available are documented in Mailmunge::Filter's
C<filter_message> documentation; these same fields are available
in C<filter_begin>, C<filter_multipart>, C<filter>, C<filter_end>
and C<filter_wrapup>.

=head2 filter_begin($ctx)

Called once at the beginning of filtering.  See
L<Mailmunge::Filter/filter_message> for the list of $ctx fields
available.

=head2 filter_multipart($ctx, $part, $fname, $extension, $type)

filter_multipart is called once for each C<multipart/*> part in the
message.  C<$part> is the sub-part being filtered and is a
MIME::Entity.  C<$fname> is the best-guess at the filename associated
with the part (if any); it is taken from the Content-Type.name or
Content-Disposition.filename MIME fields.  C<$ext> is the filename
extension I<including the leading dot> associated with C<$fname>, and
C<$type> is the MIME type of the part.

=head2 filter($ctx, $part, $fname, $extension, $type)

filter is called once for each non-multipart part in the message.
The arguments are the same as C<filter_multipart>.

=head2 filter_end($ctx)

filter_end is called once at the end of filtering.  This is the last
place you can modify the message (which you can do with
C<action_add_entity> or C<action_add_part>).

=head2 action_accept($ctx)

This method may only be called in C<filter> or C<filter_multipart>.
It causes the part to remain in the message.  If no method that removes
or modifies a part is called, then C<action_accept> is implicitly
the default.

=head2 action_drop($ctx)

This method may only be called in C<filter> or C<filter_multipart>.
It causes the part (and if multipart, all sub-parts) to be silently
removed from the message.

=head2 action_drop_with_warning($ctx, $warning)

This method may only be called in C<filter> or C<filter_multipart>.
It causes the part (and if multipart, all sub-parts) to be removed
from the message.  Additionally, a warning message is added
in a new C<text/plain> part that is appended to the message.

=head2 action_accept_with_warning($ctx, $warning)

This method may only be called in C<filter> or C<filter_multipart>.
It causes a warning message to be added in a new C<text/plain> part
that is appended to the message.

=head2 action_replace_with_warning($ctx, $warning)

This method may only be called in C<filter> or C<filter_multipart>.
It causes the part to be removed from the message and replaced
with a new C<text/plain> part containing the C<$warning> message.

=head2 action_add_entity($ctx, $entity [, $offset])

Causes a new C<MIME::Entity> to be added to the message at offset
C<$offset>, which is the zero-based index in the top-level message at
which to add the entity.  If C<$offset> is not supplied, the part is
added to the end of the message.

=head2 action_add_part($ctx, $type, $encoding, $data, $fname, $disposition, $offset)

Creates a new C<MIME::Entity> whose MIME type is C<$type>, Content-Encoding is
C<$encoding>, Content-Disposition is C<$disposition>,
Content-Disposition.filename is C<$fname> and contents are C<$data>.
Then calls action_add_entity with the new part and supplied C<$offset>.
This is really just a convenience function that builds the MIME::Entity
for you.

=head2 take_stab_at_filename($entity)

Returns Mailmunge's best-guess at the filename associated with
MIME::Entity C<$entity>.  Note that the decoded filename is
returned, so any MIME encoding is parsed and decoded.

=head1 CONVERTING FROM MIMEDefang

Conversion of a filter from MIMEDefang to Mailmunge can range from
very mechanical to quite complicated, depending on the filter.
This section is a MIMEDefang-to-Mailmunge conversion guide.

=head2 The Filter

A MIMEDefang filter is a I<fragment> of a Perl program, whereas
a Mailmunge filter is a I<complete> Perl program.

To convert a MIMEDefang filter to Mailmunge, your Mailmunge filter
should start something like this:

    package MyFilter;
    use strict;
    use warnings;

    use base qw(Mailmunge::Filter::Compat);

    my $filter = MyFilter->new();
    $filter->run();

=head2 Callbacks

Mailmunge callbacks are similar to MIMEDefang, but have different
arguments.  The Following table shows the correspondence.

 MIMEDefang                                  Mailmunge
 ==========                                  =========

 sub filter_initialize {                     sub initialize {
     # ...                                       my ($self) = @_;
 }                                               # ...
                                             }

 sub filter_cleanup {                        sub cleanup {
     # ...                                       my ($self) = @_;
 }                                               # ...
                                             }


 sub filter_relay {                          sub filter_relay {
     my ($ip, $name, $port,                      my ($self, $ctx) = @_;
         $my_ip, $my_port, $qid) = @_;           # ...
     # ...                                   }
 }


 sub filter_helo {                           sub filter_helo {
     my ($ip, $name, $helo, $port,               my ($self, $ctx) = @_;
         $my_ip, $my_port, $qid) = @_;           # ...
     # ...                                   }
 }


 sub filter_sender {                         sub filter_sender {
     my ($sender, $ip, $name, $helo) = @_;       my ($self, $ctx) = @_;
     # ...                                       # ...
 }                                           }


 sub filter_recipient {                      sub filter_recipient {
     my ($recip, $sender, $ip, $name,            my ($self, $ctx) = @_;
         $first_recip, $helo,                    # ...
         $mailer, $host, $addr) = @_;        }
         # ...
 }

 sub filter_begin {                          sub filter_begin {
     my ($entity) = @_;                          my ($self, $ctx) = @_;
     # ...                                       # ... Entity is $ctx->mime_entity
 }                                           }

 sub filter {                                sub filter {
     my ($entity, $fname,                        my ($self, $ctx, $entity, $fname,
         $extension, $mime_type) = @_;               $extension, $mime_type) = @_;
     # ...                                       # ...
 }                                           }


 sub filter_multipart {                      sub filter_multipart {
     my ($entity, $fname,                        my ($self, $ctx, $entity, $fname,
         $extension, $mime_type) = @_;               $extension, $mime_type) = @_;
     # ...                                       # ...
 }                                           }


 sub filter_end {                            sub filter_end {
     my ($entity) = @_;                          my ($self, $ctx) = @_;
     # ...                                       # ... Entity is $ctx->mime_entity
 }                                           }


 sub filter_wrapup {                         sub filter_wrapup {
     my ($entity) = @_;                          my ($self, $ctx) = @_;
     # ...                                       # ... Entity is $ctx->mime_entity
 }                                           }


 sub filter_map {                            sub filter_map {
     my ($map, $key) = @_;                       my ($self, $map, $key) = @_;
     # ...                                       # ...
 }                                           }


 sub filter_tick {                           sub tick {
     my ($tick_no) = @_;                         my ($self, $tick_no) = @_;
     # ...                                       # ...
 }                                           }


 sub filter_validate { ... }                 No equivalent in Mailmunge


 sub defang_warning { ... }                  No equivalent in Mailmunge


=head2 Return Values

Many MIMEDefang functions return an array of elements.  In Mailmunge,
they instead return a L<Mailmunge::Response> object.

 MIMEDefang                                        Mailmunge
 ==========                                        =========

 return ('CONTINUE', 'ok');                        return Mailmunge::Response->CONTINUE();

 return ('TEMPFAIL', 'Message', 421, '4.1.1');     return Mailmunge::Response->TEMPFAIL(message => 'Message', code => 421, dsn => '4.1.1');

 return ('TEMPFAIL', 'Message', 571, '5.2.1');     return Mailmunge::Response->REJECT(message => 'Message', code => 571, dsn => '5.2.1');

 return ('DISCARD', 'Message');                    return Mailmunge::Response->DISCARD(message => 'Message');

 return ('ACCEPT_AND_NO_MORE_FILTERING', 'ok');    return Mailmunge::Response->ACCEPT_AND_NO_MORE_FILTERING();

=head2 Global Variables

MIMEDefang filters make use of a plethora of global variables.  Mailmunge
does not use any global variables.  The correspondences for the most
important variables are shown below.

 MIMEDefang                                        Mailmunge
 ==========                                        =========

 $MessageID                                        $ctx->message_id
 $RealRelayAddr                                    $ctx->connecting_ip
 $RealRelayHostname                                $ctx->connecting_name
 $CWD                                              $ctx->cwd
 @ESMTPArgs                                        @{$ctx->esmtp_args}
 @SenderESMTPArgs                                  @{$ctx->esmtp_args}
 $Helo                                             $ctx->helo
 $RelayAddr                                        $ctx->hostip
 $RelayHostname                                    $ctx->hostname
 $MIMEDefangID                                     $ctx->mailmunge_id
 $MessageID                                        $ctx->message_id
 $QueueID                                          $ctx->qid
 %RecipientESMTPArgs                               %{$ctx->recipient_esmtp_args}
 @Recipients                                       @{$ctx->recipients}
 $Sender                                           $ctx->sender
 $Subject                                          $ctx->subject
 $SubjectCount                                     $ctx->subject_count
 $SuspiciousCharsInHeaders                         $ctx->suspicious_chars_in_headers
 $SuspiciousCharsInBody                            $ctx->suspicious_chars_in_body
 $WasResent                                        $ctx->was_resent

=head2 VARIOUS BITS OF MIMEDEFANG FUNCTIONALITY

Mailmunge moves a lot of functionality out of the core filter
into modules.  Here is a rough correspondence between MIMEDefang
and Mailmunge functionality.  Note that in some cases, we
recommend external CPAN modules that already have the required
functionality; duplicating that effort within Mailmunge would
not be efficient.

=over

=item DNSBL lookups

Instead of the various C<relay_is_blacklisted> functions, use
L<Net::DNSBL::Client|https://metacpan.org/pod/Net::DNSBL::Client>.

=item Streaming

Instead of C<stream_by_recipient> or C<stream_by_domain>, use
L<Mailmunge::Action::Stream>.

=item Virus-Scanning

Instead of all the C<*_contains_virus_*> functions, use
L<File::VirusScan|https://metacpan.org/pod/File::VirusScan>.

=item Bogus MX Host Checks

Instead of C<md_get_bogus_mx_hosts>, use
L<Mailmunge::Test::GetMX>.

=item Boilerplate

Instead of C<append_text_boilerplate> or C<append_html_boilerplate>,
use L<Mailmunge::Action::Boilerplate>.

=item SpamAssassin

Instead of the various C<spam_assassin_*> functions, use
L<Mailmunge::Test::SpamAssassin>.

=item Rspamd

Instead of C<rspamd_check>, use L<Mailmunge::Test::Rspamd>.

=item SMTP Call-forwards

Instead of C<md_check_against_smtp_server>, use
L<Mailmunge::Test::SMTPForward>.

=back

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
