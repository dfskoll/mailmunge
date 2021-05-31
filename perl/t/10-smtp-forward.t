use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Test::Mailmunge::SMTPServer;
use Test::Mailmunge::Utils;

use Mailmunge::Test::SMTPForward;
use Mailmunge::Filter;
use Mailmunge::Context;

my $PORT = -1;

package ForwardFilter;
use Test::Mailmunge::Filter;
use base qw(Test::Mailmunge::Filter);

sub filter_recipient
{
        my ($self, $ctx) = @_;
        my $forwarder = Mailmunge::Test::SMTPForward->new($self);
        return $forwarder->check_against_smtp_server($ctx, $ctx->recipients->[0], '127.0.0.1', $PORT);
}

package main;

# Callback for our SMTP server "RCPT To:" handler
sub rcpt {
        my ($line) = @_;
        return '451 4.7.1 Try again' if ($line =~ /tempfail/);
        return '551 5.7.1 No such user' if ($line =~ /reject/);
        return '250 2.1.0 Ok';
}


my $filter = ForwardFilter->new();

my $ctx = make_test_context();

# Try with no server running
my $result = $filter->filter_recipient($ctx);

ok($result->is_tempfail, 'Got a tempfail result if we could not connect to SMTP server');

# start a server
my $server = Test::Mailmunge::SMTPServer->new(rcpt => \&rcpt);
$PORT = $server->{port};

$result = $filter->filter_recipient($ctx);
ok($result->is_success, 'Good recipient accepted');

$ctx->{recipients} = ['reject@example.com'];
$result = $filter->filter_recipient($ctx);
ok($result->is_reject, 'Bad recipient rejected');

$ctx->{recipients} = ['tempfail@example.com'];
$result = $filter->filter_recipient($ctx);
ok($result->is_tempfail, 'Tempfail recipient tempfailed');

cmp_deeply($filter->{TEST_LOGS}, [
                   [
                    'queue-id-here',
                    'debug',
                    'check_against_smtp_server: 127.0.0.1: <reject@example.com>: 551 5.7.1 No such user'
                   ],
                   [
                    'queue-id-here',
                    'debug',
                    'check_against_smtp_server: 127.0.0.1: <tempfail@example.com>: 451 4.7.1 Try again'
                   ]
           ], 'Expected messages were logged');


done_testing;

1;
