Return-Path: <foo@example.com>
From: <foo@example.com>
To: <bar@example.com>
Subject: __SUBJECT__
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="foo"

This is a multipart message in MIME format.

--foo
Content-Type: multipart/mixed; boundary="bar"

--bar
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Hi there!  This is the first text/plain part

--bar
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Hi there!  This is the second text/plain part


--bar
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: 7bit

<html><head></head><body>
<p>Hi there!  This is the first text/html part</p>
</body>

--bar
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: 7bit

<html><head></head><body>
Hi there!  This is the second text/html part
</body>

--bar--

--foo
Content-Type: multipart/mixed; boundary="quux"

--quux
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Hi there!  This is the first text/plain part

--quux
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Hi there!  This is the second text/plain part


--quux
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: 7bit

<html><head></head><body>
<p>Hi there!  This is the first text/html part</p>
</body>

--quux
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: 7bit

<html><head></head><body>
Hi there!  This is the second text/html part
</body>

--quux--

--foo
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="foo.bin"

Blort!

--foo--
