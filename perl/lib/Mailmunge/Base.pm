use strict;
use warnings;

package Mailmunge::Base;

sub make_accessors
{
        my ($class, @vars) = @_;
        foreach my $name (@vars) {
                $class->_make_accessor($name);
        }
}

sub _make_accessor
{
        my ($class, $name) = @_;

        no strict 'refs';  ## no critic (ProhibitNoStrict)
        if (!defined &{"${class}::$name"}) {
                *{"${class}::$name"} = sub {
                        $_[0]->{$name} = $_[1] if defined($_[1]);
                        return $_[0]->{$name};
                };
        }
}

1;

__END__

=head1

Mailmunge::Base - Base class for Mailmunge objects

=head1 ABSTRACT

Mailmunge::Base offers a convenience function for creating accessors
to get and set instance variables.

=head1 SYNOPSIS

    package MyThing;
    use base qw(Mailmunge::Base);

    my @accessors = qw(height weight age);

    __PACKAGE__->make_accessors(@accessors);

    # Defines getters/setters MyThing::height, MyThing::weight and
    # MyThing::age
    my $thing = MyThing->new();
    $thing->age(20);
    my $x = $thing->height;

=head1 CLASS METHODS

=head2 make_accessors(@accessors)

Given an array of accessor names, creates getter and setter methods.
Each method is named according to the corresponding element of
C<@accessors>.  When called with no parameters, it is a getter; when
called with one parameter, it is a settor.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.
