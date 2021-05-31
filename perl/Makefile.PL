use strict;
use warnings;
use lib '.';

use inc::Module::Install;

name           'Mailmunge';
module_name    'Mailmunge';

requires       'MIME::Parser' => '5.509';
requires       'Sys::Syslog' => 0;
requires       'Sys::Hostname' => 0;
requires       'Time::Local' => 0;
requires       'MIME::Words' => '5.509';
requires       'Encode' => 0;
requires       'Carp' => 0;
requires       'Socket' => 0;
requires       'IO::Socket' => 0;
requires       'IO::Socket::SSL' => 0;

recommends     'Mail::SpamAssassin' => 3.4.2;
recommends     'File::VirusScan' => 0.103;

test_requires  'Mail::SpamAssassin' => 3.4.2;
test_requires  'File::VirusScan' => 0.103;
test_requires  'File::Find::Rule' => 0;
test_requires  'Test::More' => 0;
test_requires  'Test::Deep' => 0;

version_from   'lib/Mailmunge.pm';
author         q{Dianne Skoll <dianne@skollsoft.com>};
abstract       'Base classes for building mailmunge filters';
license        'GPL_2';

WriteAll;

