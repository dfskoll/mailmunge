use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Mailmunge::Test::GetMX;
use Test::Mailmunge::Filter;

my $filter = Test::Mailmunge::Filter->new();

my $getmx = Mailmunge::Test::GetMX->new($filter);

my $ans = $getmx->get_mx_hosts('bogus-all.mailmunge.org');

cmp_deeply($ans,
           {
                   'routable' => [
                           '42.42.42.42'
                       ],
                       'loopback' => [
                               '127.0.0.1'
                       ],
                       'bogus' => set(
                               '255.255.255.255',
                               '0.0.0.0'
                       ),
                       'private' => set(
                               '172.16.4.5',
                               '192.168.44.33',
                               '10.2.3.4'
                       )
           }, 'Got expected results from get_mx_hosts');

done_testing;
1;
