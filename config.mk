prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
man1dir = $(mandir)/man1

destdir = 
version = 0.3

inc = -I.

libs = -Llibxmpp -lxmpp -lpolarssl

CFLAGS = -O0 -g -Wall -DVERSION=\"$(version)\" $(inc)
LDFLAGS = $(libs)
LANG = C
