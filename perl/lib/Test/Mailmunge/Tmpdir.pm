use strict;
use warnings;

package Test::Mailmunge::Tmpdir;

use File::Temp qw(tempdir);
use File::Path qw(remove_tree);
use File::Spec;

sub new
{
        my ($class) = @_;

        mkdir('t/tmp', 0755);

        my $dir = tempdir(DIR => 't/tmp', CLEANUP => 0);

        $dir = File::Spec->rel2abs($dir);

        my $self = bless { dir => $dir, cleanup => 1}, $class;
        return $self;
}

sub DESTROY
{
        my ($self) = @_;
        return unless $self->{cleanup};
        return unless $self->{dir};

        remove_tree($self->{dir});
}

1;

__END__

=head1 NAME

Test::Mailmunge::Tmpdir - create and (usually) clean up a temporary directory

=head1 ABSTRACT

Test::Mailmunge::Tmpdir creates a temporary directory under
C<./t/tmp> and (unless told otherwise) removes it just before
the program exits.  More specifically, the directory
is removed with the C<Test::Mailmunge::Tmpdir> object goes
out of scope.

=head1 SYNOPSIS

    use Test::Mailmunge::Tmpdir;

    my $tmp_obj = Test::Mailmunge::Tmpdir->new();
    my $dir = $tmp_obj->{dir};

    # Create files, etc in $dir

    if (something_went_horribly_wrong()) {
        # Oh no!  Don't clean up the temp dir
        $tmp_obj->{cleanup} = 0;
    }

    # Directory will be cleaned up prior to exit
    # unless we set $tmp_obj->{cleanup} to 0.
    exit(0);

=head1 CONSTRUCTOR

=head2 Test::Mailmunge::Tmpdir->new()

Returns a new object C<$tmp_obj>.  The newly-created
temporary directory is in C<$tmp_obj-E<gt>{dir}> and
the "cleanup" flag is in C<$tmp_obj-E<gt>{cleanup}>.

=head1 AUTHOR

Dianne Skoll <dianne@skollsoft.com>

=head1 LICENSE

This code is licensed under the terms of the GNU General Public License,
version 2.

