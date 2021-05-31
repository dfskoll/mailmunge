use lib '.';
use Test::More;

use Test::Mailmunge::RegressionUtils;

use Mailmunge::Filter;

my $filter = Mailmunge::Filter->new();

if (server_running_postfix()) {
        ok($filter->mta_is_postfix(), "mta_is_postfix() returns true");
        ok(!$filter->mta_is_sendmail(), "mta_is_sendmail() returns false");
} else {
        ok(!$filter->mta_is_postfix(), "mta_is_postfix() returns false");
        ok($filter->mta_is_sendmail(), "mta_is_sendmail() returns true");
}

done_testing;

1;
