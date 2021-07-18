use strict;
use warnings;

use lib './lib';

use Test::More;

use Mailmunge::Test::Greylist;
use Test::Mailmunge::Filter;

use DBI;
my $dbh;

sub make_database
{
        unlink('t/tmp/greylist.sqlite');
        $dbh = DBI->connect('dbi:SQLite:dbname=t/tmp/greylist.sqlite') or die("Unable to create SQLite database: $!");
        $dbh->do(q{CREATE TABLE greylist(hash TEXT PRIMARY KEY NOT NULL, last_seen INTEGER)});
        $dbh->do(q{CREATE TABLE ips_known_to_retry(ip TEXT PRIMARY KEY NOT NULL, last_seen INTEGER)});
}

make_database();

my $filter = Test::Mailmunge::Filter->new();
my $gl = Mailmunge::Test::Greylist->new($filter);

# First time should fail
my $ans = $gl->evaluate($dbh, 0, 86400, '1.2.3.4', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_tempfail, 'Got a tempfail response from greylisting the first time around');

# Second time should succeed
$ans = $gl->evaluate($dbh, 0, 86400, '1.2.3.4', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_success, 'Got a success response from greylisting the second time around');

# Now let's try with a minimum wait time
# First time should fail
$ans = $gl->evaluate($dbh, 2, 86400, '1.2.1.5', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_tempfail, 'Got a tempfail response from greylisting the first time around');

# Second time should also fail
$ans = $gl->evaluate($dbh, 2, 86400, '1.2.1.5', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_tempfail, 'Got a tempfail response from greylisting the second time around');

# Wait a bit
sleep(2);

# Third time should work
$ans = $gl->evaluate($dbh, 2, 86400, '1.2.1.5', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_success, 'Got a success response from greylisting the third time around');

# One more that never retries
$ans = $gl->evaluate($dbh, 2, 86400, '1.2.3.8', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_tempfail, 'Got a tempfail response from greylisting the first time around');

# Check the DB for sanity
$ans = $dbh->selectrow_arrayref(q{SELECT COUNT(*) FROM greylist});
is ($ans->[0], 3, 'There are three rows in the greylist table');
$ans = $dbh->selectrow_arrayref(q{SELECT COUNT(*) FROM ips_known_to_retry});
is ($ans->[0], 2, 'There are two rows in the ips_known_to_retry table');


# Clear out the greylist table, but our existing IPs are known to pass
# and should continue to pass
$dbh->do(q{DELETE FROM greylist});

$ans = $gl->evaluate($dbh, 2, 86400, '1.2.1.5', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_success, '1.2.1.5 is not greylisted - it is known to pass');
$ans = $gl->evaluate($dbh, 2, 86400, '1.2.3.4', '<sender@example.com>', '<recipient@example.org>');
ok($ans->is_success, '1.2.3.4 is not greylisted - it is known to pass');

$dbh->disconnect();
unlink('t/tmp/greylist.sqlite');
done_testing;
1;
