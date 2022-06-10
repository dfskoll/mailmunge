#!/bin/sh
VERSION="$1"
if test "$VERSION" = "" ; then
    echo "Usage: $0 VERSION"
    exit 1
fi

if test -d .git ; then
    # git archive --worktree-attributes --format=tar
    # --prefix=mailmunge-$VERSION/ --add-file=spec/mailmunge.spec HEAD | gzip -9 > mailmunge-$VERSION.tar.gz
    git archive --worktree-attributes --format=tar --prefix=mailmunge-$VERSION/spec/ --add-file=spec/mailmunge.spec --prefix=mailmunge-$VERSION/ HEAD | gzip -9 > mailmunge-$VERSION.tar.gz
    exit $?
elif tar --help 2>&1 | grep -e --transform= > /dev/null 2>&1 ; then
    tar cf - --files-from=DIST-CONTENTS --transform=s+^+mailmunge-$VERSION/+ | gzip -9 > mailmunge-$VERSION.tar.gz
    exit 0
fi

# No dice
echo "*** 'make dist' requires you to be working in a git repo"
echo "*** or to have GNU tar.  Neither seems to be the case."
exit 1
