From: <user1@example.com>
To: <user1@example.com>
Subject: __SUBJECT__
X-Mailmunge-Drop: maildrop.msg
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="foo"

--foo
Content-Type: text/plain

Hello.

This is a message with an exe that should be silently deleted.

Sweeeeeet.

--foo
Content-Type: application/octet-stream; name="drop.exe"
Content-Disposition: attachment; filename="drop.exe"
Content-Transfer-Encoding: base64

d29va2llcG9vCg==

--foo--
