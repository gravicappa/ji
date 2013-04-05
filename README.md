Introduction
------------
ji is a minimalistic FIFO and filesystem based XMPP client. It creates
a xmpp directory tree with server and contact jid directories. In
every directory a FIFO file (`in`) and a normal file (`out`)
is placed.

The out file in xmpp directory contains server messages (such as
roster items and contact status changes). The in file is used to
control ji: open communications with groupchat rooms or with persons,
query roster items. For every chatroom and contact there will be new
directory with own in and out files.

The basic idea of this is to be able to communicate with a XMPP server
with basic command line tools.

Requirements
------------
Required [libxmpp library](https://github.com/gravicappa/libxmpps)
and [polarssl](http://polarssl.org).

Building
--------
Edit config.mk to match your local setup. Then type (as root if necessary):

    make clean install

Running
-------

    ji -j jabber@id <password_file

or if you are GTalk user:

    ji -j .....@gmail.com -s talk.google.com <password_file

where `password_file` is a file containing only your password in a single
line.

Contacts
--------
* jid: ramil.fh@jabber.ru
* mail: ramil (at) gmx (dot) co (dot) uk
