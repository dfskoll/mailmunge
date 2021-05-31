package Mailmunge::Test;
use strict;
use warnings;

use base qw(Mailmunge::Action);

1;

__END__

=head1 NAME

Mailmunge::Test - base class for Mailmunge Test plugins

=head1 ABSTRACT

This is a convenience base class that simply hangs on to a copy
of the current Mailmunge::Filter object.

=head1 SYNOPSIS

    package MyTest;
    use base qw(Mailmunge::Test);

    sub my_test_functionality { ... };
    # And then inside your filter...
    my $test = MyTest->new($self);
    my $result = $test->my_test_functionality($ctx);

=head1 METHODS

All methods are inherited from L<Mailmunge::Action>

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.
