#!/bin/bash
#
# Qualify our hostname in /etc/hosts
#

# Fix up /etc/hosts
grep 'example.com' /etc/hosts > /dev/null 2>&1
if test "$?" != "0" ; then
    H=`hostname`
    sed -e "s/\(.*\)$H/\\1$H.example.com $H/" < /etc/hosts > /etc/hosts.new && cp -f /etc/hosts.new /etc/hosts && rm -f /etc/hosts.new
fi
