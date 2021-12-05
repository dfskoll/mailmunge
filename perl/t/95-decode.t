use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Mailmunge::Filter;

my $test_cases = [
        ['foo bar baz', 'foo bar baz'],
        ['=?utf-8?Q?Mailmunge=E2=84=A2?=', "Mailmunge\x{2122}"],
        ['=?UTF-8?B?8J2ZjfCdmLzwnZmI8J2Zi/CdmLzwnZmJ8J2Zj/CdmYfwnZmUIHwgVmlydHVhbCBDb21lZA==?= =?UTF-8?B?eSBNYWNoaW5lIHNlbnQgeW91IGEgbmV3IG1lc3NhZ2U=?=', "\x{1D64D}\x{1D63C}\x{1D648}\x{1D64B}\x{1D63C}\x{1D649}\x{1D64F}\x{1D647}\x{1D654} | Virtual Comedy Machine sent you a new message"],
        ['=?ISO-8859-1?Q?Payroll_submission_reminder_/_Rappel_pou?=  =?ISO-8859-1?Q?r_la_transmission_des_donn=E9es_de_la_paie?=', "Payroll submission reminder / Rappel pour la transmission des donn\x{e9}es de la paie"],
        ['=?ISO-8859-1?Q?Payroll_submission_reminder_/_Rappel_pou?=  =?UTF-8?Q?r_la_transmission_des_donn=C3=A9es_de_la_paie?=', "Payroll submission reminder / Rappel pour la transmission des donn\x{e9}es de la paie"],
];

foreach my $case (@$test_cases) {
        my $in = $case->[0];
        my $expected = $case->[1];
        my $ans = Mailmunge::Filter->decode_mime_string($in);
        is ($ans, $expected, "Got expected decoded string for \"$in\"");
}

done_testing;

1;
