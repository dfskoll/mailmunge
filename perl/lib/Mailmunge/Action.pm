package Mailmunge::Action;
use strict;
use warnings;

sub new
{
        my ($class, $filter) = @_;
        return bless { filter => $filter }, $class;
}

sub filter
{
        my ($self) = @_;
        return $self->{filter};
}

1;

__END__
=head1 NAME

Mailmunge::Action - base class for Action and Test Mailmunge plugins

=head1 ABSTRACT

This is a convenience base class that simply hangs on to a copy
of the current Mailmunge::Filter object.

=head1 SYNOPSIS

    package MyAction;
    use base qw(Mailmunge::Action);

    sub my_action_functionality { ... };
    # And then inside your filter...
    my $action = MyAction->new($self);
    $action->my_action_functionality($ctx);

=head1 CLASS METHODS

=head2 Mailmunge::Action->new($filter)

Constructs a new Mailmunge::Action object and stores a copy of $filter
in it

=head1 INSTANCE METHODS

=head2 filter()

Returns the Mailmunge::Filter object supplied to the constructor.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licened under the terms of the GNU General Public License,
version 2.
