#!/bin/bash
#
# Set up Docker machine for tests
#

# Change into this directory so we can find files
cd `dirname $0` || exit 1

# Delete ALL_TRUSTED spamassassin rule file
rm -f /usr/share/spamassassin/20_compensate.cf

# Restart rsyslog
/etc/init.d/rsyslog restart

# Fix up /etc/hosts
grep 'example.com' /etc/hosts > /dev/null 2>&1
if test "$?" != "0" ; then
    H=`hostname`
    sed -e "s/\(.*\)$H/\\1$H.example.com $H/" < /etc/hosts > /etc/hosts.new && cp -f /etc/hosts.new /etc/hosts && rm -f /etc/hosts.new
fi

if test -d /etc/postfix ; then
    # POSTFIX-SPECIFIC CODE
    # Add smtpd_milters line to /etc/postfix/main.cf if it's not
    # already there
    RESTART_POSTFIX=0
    grep ^smtpd_milters /etc/postfix/main.cf > /dev/null 2>&1
    if test $? != 0 ; then
        echo 'smtpd_milters = inet:127.0.0.1:8872' >> /etc/postfix/main.cf
        RESTART_POSTFIX=1
    fi
    grep ^non_smtpd_milters /etc/postfix/main.cf > /dev/null 2>&1
    if test $? != 0 ; then
        echo 'non_smtpd_milters = inet:127.0.0.1:8872' >> /etc/postfix/main.cf
        RESTART_POSTFIX=1
    fi

    # Fix mydestination
    fgrep example.com /etc/postfix/main.cf > /dev/null 2>&1
    if test $? != 0 ; then
        sed -i -e 's/mydestination = .*/mydestination = $myhostname, localhost.localdomain, localhost, example.com, example.net, example.org/' /etc/postfix/main.cf
        RESTART_POSTFIX=1
    fi
    if test "$RESTART_POSTFIX" != "0" ; then
        /etc/init.d/postfix restart
    fi
else
    # SENDMAIL-SPECIFIC CODE
    RESTART_SENDMAIL=0
    # Turn off rate-limiting
    for i in conncontrol ratecontrol ; do 
        fgrep $i /etc/mail/sendmail.mc > /dev/null 2>&1
        if test "$?" = 0; then
            fgrep -v $i /etc/mail/sendmail.mc > /etc/mail/sendmail.mc.new
            mv /etc/mail/sendmail.mc.new /etc/mail/sendmail.mc
            RESTART_SENDMAIL=1
        fi
    done

    grep 'DAEMON_OPTIONS\(.*Addr=127.0.0.1\)' /etc/mail/sendmail.mc
    if test $? = 0 ; then
        # Make Sendmail listen on all addresses, not just localhost
        sed -i -e 's/, Addr=127.0.0.1//g' /etc/mail/sendmail.mc
        RESTART_SENDMAIL=1
    fi

    grep '^INPUT_MAIL_FILTER' /etc/mail/sendmail.mc > /dev/null 2>&1
    if test $? != 0 ; then
        echo "INPUT_MAIL_FILTER(\`mailmunge', \`S=inet:8872@127.0.0.1, F=T, T=S:360s;R:360s;E:15m')dnl" >> /etc/mail/sendmail.mc
        RESTART_SENDMAIL=1
    fi
    for i in example.com example.net example.org ; do
        fgrep $i /etc/mail/local-host-names > /dev/null 2>&1
        if test $? != 0 ; then
            echo "$i" >> /etc/mail/local-host-names
            RESTART_SENDMAIL=1
        fi
    done
    if test "$RESTART_SENDMAIL" != "0" ; then
        make -C /etc/mail
        pkill sendmail
        /etc/init.d/sendmail restart
    fi
fi

# For postfix, alias file is /etc/aliases.  For Sendmail,
# it is /etc/mail/aliases
if test -d /etc/postfix ; then
    ALIAS_FILE=/etc/aliases
else
    ALIAS_FILE=/etc/mail/aliases
fi

# Update aliases
REBUILD_ALIASES=0
for i in `seq 1 5` ; do
    fgrep "user$i" $ALIAS_FILE > /dev/null 2>&1
    if test $? != 0 ; then
        echo "user$i: \"|/usr/local/bin/mailmunge-test-savemail.pl user$i\"" >> $ALIAS_FILE
        REBUILD_ALIASES=1
    fi
done

for i in continue reject tempfail accept_and_no_more_filtering ; do
    fgrep $i $ALIAS_FILE > /dev/null 2>&1
    if test $? != 0 ; then
        echo "$i: /dev/null" >> $ALIAS_FILE
        REBUILD_ALIASES=1
    fi
done

if test "$REBUILD_ALIASES" != "0" ; then
    newaliases
fi

# copy etc-default-mailmunge to /etc/default/mailmunge
mkdir -p /etc/default
cp etc-default-mailmunge /etc/default/mailmunge || exit 1

# Copy mailmunge-test-savemail.pl
cp mailmunge-test-savemail.pl /usr/local/bin && chmod 755 /usr/local/bin/mailmunge-test-savemail.pl

# Get virus database
freshclam || true
/etc/init.d/clamav-daemon restart

exit 0
