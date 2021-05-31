package Mailmunge::Test::GetMX;
use strict;
use warnings;

use base qw(Mailmunge::Test);

use Net::DNS;

sub _is_ip
{
        my $self = shift;
        return 0 unless scalar(@_) == 4;
        foreach my $octet (@_) {
		return 0 if ($octet !~ /^\d+$/);
		return 0 if ($octet > 255);
	}
        return 1;
}

sub ip4_is_loopback
{
        my ($self, $ip) = @_;
        my (@octets) = split(/\./, $ip);
        return 0 unless $self->_is_ip(@octets);

        return 1 if $octets[0] == 127;
        return 0;
}

sub ip4_is_private
{
        my ($self, $ip) = @_;
        my (@octets) = split(/\./, $ip);
        return 0 unless $self->_is_ip(@octets);

	# 10.0.0.0 to 10.255.255.255
	return 1 if ($octets[0] == 10);

	# 172.16.0.0 to 172.31.255.255
	return 1 if ($octets[0] == 172 && $octets[1] >= 16 && $octets[1] <= 31);

	# 192.168.0.0 to 192.168.255.255
	return 1 if ($octets[0] == 192 && $octets[1] == 168);
}

sub ip4_is_reserved
{
        my ($self, $ip) = @_;
        my (@octets) = split(/\./, $ip);
        return 0 unless $self->_is_ip(@octets);

        # Local-link for auto-DHCP
	return 1 if ($octets[0] == 169 && $octets[1] == 254);

	# IPv4 multicast
	return 1 if ($octets[0] >= 224 && $octets[0] <= 239);

	# Class E ("Don't Use")
	return 1 if ($octets[0] >= 240 && $octets[0] <= 247);

	# 0.0.0.0 and 255.255.255.255 are bogus
	return 1 if (($octets[0] | $octets[1] | $octets[2] | $octets[3]) == 0);
	return 1 if (($octets[0] & $octets[1] & $octets[2] & $octets[3]) == 255);

	return 0;
}

sub _get_mx_ip_addresses {
        my ($self, $domain) = @_;

        my @mx_ips;
        my $res = Net::DNS::Resolver->new;
        $res->defnames(0);

        my $pkt = $res->query($domain, 'MX');
        if (!defined($pkt) ||
            $pkt->header->rcode eq 'SERVFAIL' ||
            $pkt->header->rcode eq 'NXDOMAINE' ||
            !defined($pkt->answer)) {
                # No MX records.  Try A.
		$pkt = $res->query($domain, 'A');
		if (!defined($pkt) ||
		    $pkt->header->rcode eq 'SERVFAIL' ||
		    $pkt->header->rcode eq 'NXDOMAIN' ||
		    !defined($pkt->answer)) {
			return @mx_ips;
		}
        }

	foreach my $item ($pkt->answer) {
		if ($item->type eq 'MX') {
			# Weird MX record of "." or ""
			# host -t mx yahoo.com.pk for example
			if ($item->exchange eq ''   ||  $item->exchange eq '.'   || $item->exchange eq '0' ||
			    $item->exchange eq '0 ' ||  $item->exchange eq '0 .' || $item->exchange eq '0.') {
				push(@mx_ips, '0.0.0.0');
				next;
			}

			# If it LOOKS like an IPv4 address, don't do
			# an A lookup
			if ($item->exchange =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.?$/) {
				my ($a, $b, $c, $d) = ($1, $2, $3, $4);
				if ($a <= 255 && $b <= 255 && $c <= 255 && $d <= 255) {
					push(@mx_ips, "$a.$b.$c.$d");
					next;
				}
			}

                        # Do A lookup
			my $pkt2 = $res->query($item->exchange, 'A');
			next unless defined($pkt2);
			next if $pkt2->header->rcode eq 'SERVFAIL';
			next if $pkt2->header->rcode eq 'NXDOMAIN';
			next unless defined($pkt2->answer);
			foreach my $item2 ($pkt2->answer) {
                                push(@mx_ips, $item2->address) if ($item2->type eq 'A');
			}
		} elsif ($item->type eq 'A') {
			push(@mx_ips, $item->address);
		}
        }
        return @mx_ips;
}

sub get_mx_hosts
{
        my ($self, $domain) = @_;

        # Convert email address to just domain
        $domain = $self->filter->domain_of($domain) if $domain =~ /\@/;

        my @bogus;
        my @mx_ips = $self->_get_mx_ip_addresses($domain);

        my $ans = { bogus => [],
                    private => [],
                    loopback => [],
                    routable => [] };

        foreach my $ip (@mx_ips) {
                if ($self->ip4_is_loopback($ip)) {
                        push(@{$ans->{loopback}}, $ip);
                } elsif ($self->ip4_is_private($ip)) {
                        push(@{$ans->{private}}, $ip);
                } elsif ($self->ip4_is_reserved($ip)) {
                        push(@{$ans->{bogus}}, $ip);
                } else {
                        push(@{$ans->{routable}}, $ip);
                }
        }
        return $ans;
}

1;

__END__

=head1 NAME

Mailmunge::Test::GetMX - Get the MX records for a domain and classify them

=head1 ABSTRACT

This class performs an MX lookup on a given domain and returns the IPv4
addresses of the MX hosts, classifying each IP address as described below.

C<Mailmunge::Test::GetMX> is a subclass of C<Mailmunge::Test>.

=head1 SYNOPSIS

    use Mailmunge::Test::GetMX;

    sub filter_sender {
        my ($self, $ctx) = @_;
        my $getmx = Mailmunge::Test::GetMX->new($self);
        my $results = $getmx->get_mx_hosts($ctx->sender);
        if (scalar(@{$results->{bogus}}) {
            $self->log($ctx, 'info', "Found reserved IPs in MX for " . $ctx->sender);
        }
        if (scalar(@{$results->{private}}) {
            $self->log($ctx, 'info', "Found RFC 1918 IPs in MX for " . $ctx->sender);
        }
        if (scalar(@{$results->{loopback}}) {
            $self->log($ctx, 'info', "Found RFC loopback IPs in MX for " . $ctx->sender);
        }
        if (scalar(@{$results->{routable}}) {
            $self->log($ctx, 'info', "Found valid routable IPs in MX for " . $ctx->sender);
        }
    }

=head1 CONSTRUCTOR

=head2 Mailmunge::Test::GetMX->new($filter)

Constructs and returns a new Mailmunge::Test::GetMX object.

=head2 get_mx_hosts($domain_or_sender)

Given a domain or an email address, looks up the MX hosts of the
domain (or domain of the sender) and returns a hash containing
the following four elements:

=over

=item bogus

An arrayref of MX hosts IPs that have bogus unroutable IP addresses
(such as 0.0.0.0, 255.255.255.255, or multicast addresses, for example.)

=item private

An arrayref of MX host IPs that are in the RFC 1918 private use ranges.

=item loopback

An arrayref of MX host IPs that are in the range 127.0.0.0/8.

=item routable

An arrayref of MX host IPs that are globally-routable unicast IPv4
addresses.

=back

You may wish to have your filter reject mail from domains that
have bogus MX records; make your decision based on the value
returned from get_mx_hosts.

=head2 ip4_is_loopback($ip)

Given the string representation of an IPv4 address, returns
true if it's in the range 127.0.0.0/8 or false otherwise.

=head2 ip4_is_private($ip)

Given the string representation of an IPv4 address, returns
true if it's in one of the RFC 1918 private ranges or
false otherwise.


=head2 ip4_is_reserved($ip)

Given the string representation of an IPv4 address, returns
true if it's in one of the following ranges:

=over

=item Link-local

169.254.0.0/16

=item IPv4 Multicast

224.0.0.0/4

=item Class E

224.0.0.0/4

=item Bogus

0.0.0.0/32 and 255.255.255.255/32

=back

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.
