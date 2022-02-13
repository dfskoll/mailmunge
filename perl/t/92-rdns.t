use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Mailmunge::Filter;
use Test::Mailmunge::Utils;

unless (dns_available()) {
        plan skip_all => 'This test requires working DNS';
}

my $name = Mailmunge::Filter->ip_to_hostname('8.8.8.8');
is($name, 'dns.google', 'Successfully reverse-resolved 8.8.8.8 with FCrDNS');

$name = Mailmunge::Filter->ip_to_hostname('2001:4860:4860::8888');
is($name, 'dns.google', 'Successfully reverse-resolved 2001:4860:4860::8888 with FCrDNS');

$name = Mailmunge::Filter->ip_to_hostname('8.8.8.8', 0);
is($name, 'dns.google', 'Successfully reverse-resolved 8.8.8.8 without FCrDNS');

$name = Mailmunge::Filter->ip_to_hostname('2001:4860:4860::8888', 0);
is($name, 'dns.google', 'Successfully reverse-resolved 2001:4860:4860::8888 without FCrDNS');

done_testing;
1;
