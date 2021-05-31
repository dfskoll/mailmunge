#!/usr/bin/env perl
use strict;
use warnings;

use File::Basename;
use IO::File;
my $dest = $ARGV[0] || 'unknown';

my $drop_dir = '/tmp/mailmunge-drop';

my $old_umask = umask(0);
mkdir($drop_dir, 0755);
umask($old_umask);

my $msg;
my $file = 'maildrop.msg';

{ local $/; $msg = <STDIN>; }

if ($msg =~ m/^X-Mailmunge-Drop: \s*(.*)$/m) {
        $file = $1;
        $file =~ s[/\.\./][/];  # Remove .. in path
        $file =~ s[/+][/];      # Remove multiple /
        $file =~ s[^/][];       # Remove leading / if present
        $file =~ s/%DEST%/$dest/g; # Replace %DEST% with actual destination
        $file = basename($file);
}

$old_umask = umask(0);
my $fh = IO::File->new("$drop_dir/$file.tmp", 'w', 0644);
umask($old_umask);
$msg =~ s/\n\n/\nX-MM-Delivered: $dest\n\n/s;
$fh->print($msg);
$fh->close();
rename("$drop_dir/$file.tmp", "$drop_dir/$file");
exit(0);
