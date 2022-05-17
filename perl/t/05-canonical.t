use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Mailmunge::Response;
use Mailmunge::Context;
use Mailmunge::Filter;

my $testcases = {
        '<foo@example.com>' => 'foo@example.com',
        '<FOO@ExAMpLE.ORg>' => 'foo@example.org',
        'FOO@ExAMpLE.ORg>' => 'foo@example.org',
        '<FOO@ExAMpLE.ORg' => 'foo@example.org',
        'FOO@ExAMpLE.ORg' => 'foo@example.org',
        '<>' => '',
        '<<blat>>' => '<blat>',
};

while (my ($in, $expected) = each(%$testcases)) {
        is (Mailmunge::Filter->canonical_email($in), $expected, "canonical_email($in) returned $expected");
}

my $ctx = Mailmunge::Context->new(sender => '<FOO@Example.org>',
                                  recipients => ['bar@x.com', '<Quux@zot.COM>', '<LOGY@LOGY.EXAMPLE>']);

is($ctx->canonical_sender, 'foo@example.org', '$ctx->canonical_sender works');
cmp_deeply($ctx->canonical_recipients, ['bar@x.com', 'quux@zot.com', 'logy@logy.example'], '$ctx->canonical_recipients works');

$testcases = {
        '<foo@example.com>' => 'example.com',
        '<FOO@ExAMpLE.ORg>' => 'example.org',
        'FOO@ExAMpLE.ORg>' => 'example.org',
        '<FOO@ExAMpLE.ORg' => 'example.org',
        'F@barOO@ExAMpLE.ORg' => 'example.org',
        '<<blat>>' => '<blat>',
        '<<x@blat>>' => 'blat>',
};

while (my ($in, $expected) = each(%$testcases)) {
        is (Mailmunge::Filter->domain_of($in), $expected, "domain_of($in) returned $expected");
}

done_testing;
