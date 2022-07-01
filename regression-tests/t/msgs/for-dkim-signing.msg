Return-Path: <foo@test.mailmunge.org>
Received: from box.example.com (box.example.com [192.168.1.1])
	by pi4.skoll.ca (Postfix) with ESMTPS id 4LZ4325WrSzgd63b
	for <bar@example.com>; Fri,  1 Jul 2022 01:47:10 -0400 (EDT)
Received: from box.example.com ([10.0.0.1])
	by box.example.com (8.15.2/8.15.2/Debian-22) with ESMTP id 2615l90J399696;
	Fri, 1 Jul 2022 01:47:09 -0400
From: <foo@test.mailmunge.org>
X-Mailmunge-Drop: dkim.msg
To: <bar@example.com>
Date: Fri,  1 Jul 2022 14:57:59 +0000 (UTC)
Message-Id: <20220701145759.6181D4720A8C@ec718c1aae59.mailmunge.org>
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
