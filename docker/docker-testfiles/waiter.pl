#!/usr/bin/perl
#
# Run this as PID-1 in a docker container to reap zombies
#
use strict;
use warnings;

sub waiter
{
        while (wait() > 0) {
        }
}

$SIG{CHLD} = \&waiter;

while(1) {
        sleep(5);
        waiter();
}
