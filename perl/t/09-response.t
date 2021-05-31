use strict;
use warnings;

use lib './lib';

use Test::More;
use Test::Deep;

use Mailmunge::Response;

my $resp;

$resp = Mailmunge::Response->CONTINUE(message => 'You are cool');

cmp_deeply($resp, bless( {
        'status' => 'CONTINUE',
            'delay' => 0,
            'message' => 'You are cool'}, 'Mailmunge::Response' ), 'Got expected response');

$resp->fix_code_dsn();

cmp_deeply($resp, bless( {
        'status' => 'CONTINUE',
            'code' => 250,
            'dsn' => '2.1.0',
            'delay' => 0,
            'message' => 'You are cool'}, 'Mailmunge::Response' ), 'Got expected code and DSN');

$resp = Mailmunge::Response->TEMPFAIL(message => 'I do not like you');

cmp_deeply($resp, bless( {
        'status' => 'TEMPFAIL',
            'delay' => 0,
            'message' => 'I do not like you'}, 'Mailmunge::Response' ), 'Got expected response');

$resp->fix_code_dsn();

cmp_deeply($resp, bless( {
        'status' => 'TEMPFAIL',
            'code' => 451,
            'dsn' => '4.3.0',
            'delay' => 0,
            'message' => 'I do not like you'}, 'Mailmunge::Response' ), 'Got expected code and DSN');

$resp = Mailmunge::Response->REJECT(message => 'GO AWAY');

cmp_deeply($resp, bless( {
        'status' => 'REJECT',
            'delay' => 0,
            'message' => 'GO AWAY'}, 'Mailmunge::Response' ), 'Got expected response');

$resp->fix_code_dsn();

cmp_deeply($resp, bless( {
        'status' => 'REJECT',
            'code' => 554,
            'dsn' => '5.7.1',
            'delay' => 0,
            'message' => 'GO AWAY'}, 'Mailmunge::Response' ), 'Got expected code and DSN');

$resp = Mailmunge::Response->REJECT(message => 'GO AWAY', code => '200', dsn => '5.0.2');

cmp_deeply($resp, bless( {
        'status' => 'REJECT',
            'delay' => 0,
            'code' => 200,
            'dsn' => '5.0.2',
            'message' => 'GO AWAY'}, 'Mailmunge::Response' ), 'Got expected response');

$resp->fix_code_dsn();

cmp_deeply($resp, bless( {
        'status' => 'REJECT',
            'code' => 554,
            'dsn' => '5.0.2',
            'delay' => 0,
            'message' => 'GO AWAY'}, 'Mailmunge::Response' ), 'Got expected code and DSN');

done_testing;
