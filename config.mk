prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
man1dir = $(mandir)/man1

destdir = 
version = 0.6

inc = -I.

libs = -Llibxmpps -lxmpps -lpolarssl

CFLAGS = -Os -Wall -DVERSION=\"$(version)\" $(inc)
LDFLAGS = $(libs)
LANG = C
