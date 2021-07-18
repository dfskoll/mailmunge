package Mailmunge::Test::Greylist;
use strict;
use warnings;

use base qw(Mailmunge::Test);

use Digest::SHA qw(sha1_hex);

sub evaluate
{
        my $self = shift;
        my $dbh = shift;
        my $min_delay = shift;
        my $max_delay = shift;
        my $ip = shift;
        my $now = time;

        # max_delay must be at least 4 hours
        $max_delay = 4*3600 if $max_delay < 4*3600;

        # The IP and any remaining arguments, separated by <>, get hashed
        my $hash = sha1_hex(join('<>', $ip, @_));

        # If this IP has been known to retry within the last 31 days,
        # don't try greylisting
        my $data = $dbh->selectrow_hashref(q{SELECT ip FROM ips_known_to_retry WHERE ip = ? AND last_seen >= ?}, undef, $ip, ($now - 31*86400));
        return Mailmunge::Response->CONTINUE if $data;

        # Check the greylist entry
        $data = $dbh->selectrow_hashref(q{SELECT last_seen FROM greylist WHERE hash = ?}, undef, $hash);
        if ($data) {
                if ($now - $data->{last_seen} > $max_delay) {
                        # Waited too long... delete the greylist record and tempfail
                        $dbh->do(q{DELETE FROM greylist WHERE hash = ?}, undef, $hash);
                        return Mailmunge::Response->TEMPFAIL(message => "Greylisting in effect; please try again in $min_delay second(s)");
                }

                if ($now - $data->{last_seen} < $min_delay) {
                        # Didn't wait long enough... return tempfail
                        return Mailmunge::Response->TEMPFAIL(message => "Greylisting in effect; please try again in $min_delay second(s)");
                }

                # Insert into ips_known_to_retry
                $dbh->do(q{INSERT INTO ips_known_to_retry(ip, last_seen) VALUES(?, ?)}, undef, $ip, $now);

                return Mailmunge::Response->CONTINUE;
        }
        $dbh->do(q{INSERT INTO greylist(last_seen, hash) VALUES(?, ?)}, undef, $now, $hash);
        return Mailmunge::Response->TEMPFAIL(message => "Greylisting in effect; please try again in $min_delay second(s)");
}

1;

__END__

=head1 NAME

Mailmunge::Test::Greylist - implementation of greylist

=head1 ABSTRACT

This class implements greylisting: Temporarily-failing a combination
of machine, sender, and recipient (and possibly other data) that
has never seen before.

C<Mailmunge::Test::Greylist> is a subclass of C<Mailmunge::Test>

=head1 SYNOPSIS

    # A database must have been created beforehand with
    # the following schema:
    #
    # CREATE TABLE greylist(hash TEXT PRIMARY KEY NOT NULL, last_seen INTEGER);
    # CREATE TABLE ips_known_to_retry(ip TEXT PRIMARY KEY NOT NULL, last_seen INTEGER);

    my $dbh;

    sub initialize {
        # Always connect to the database in the "initialize" callback
        $dbh = DBI->connect($dsn, $username, $auth, {attr => val});
    }

    sub cleanup {
        # Tidy up when our filter is about to exit
        $dbh->disconnect;
    }

    # The actual use of Mailmunge::Test::Greylist
    sub filter_recipient {
        my ($ctx) = @_;
        my $gl = Mailmunge::Test::Greylist->new($self);
        my $min_delay = 5;
        my $max_delay = 86400;
        my $result = $gl->evaluate($dbh, $min_delay, $max_delay,
                                   $ctx->hostip, $ctx->sender,
                                   $ctx->recipients->[0]);
        return $result unless $result->is_success;
        # ...
    }

=head1 CONSTRUCTOR

=head2 Mailmunge::Test::Greylist->new($filter)

Constructs and returns a new Mailmunge::Test::Greylist object

=head1 METHODS

=head2 evaluate($dbh, $min_delay, $max_delay, $ip, @remaining_args)

Evaluates greylisting and returns a C<Mailmunge::Response> object that
will either be CONTINUE or TEMPFAIL.

$dbh is a DBI handle connected to the greylisting database.

$min_delay and $max_delay are the imposed minimum and maximum retry delays
respectively.  If an SMTP client tries faster than the minimum delay, it
continues to get greylisted.  If it waits longer than the maximum delay,
it begins the greylisting test from scratch.

$ip is the IP address of the connecting SMTP client.

@remaining_args are any other arguments that should be considered to
make the greylist tuple specific.  Typically, you would call
C<evaluate> from C<filter_recipient> and would pass the sender
and recipient as @remaining_args

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licenced under the terms of the GNU General Public License,
version 2.

