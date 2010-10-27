prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/share/man
man1dir = $(mandir)/man1

destdir = 
version = 0.2

inc = $(shell pkg-config --cflags iksemel) \
      $(shell pkg-config --cflags gnutls)

libs = -lutil \
       $(shell pkg-config --libs iksemel) \
       $(shell pkg-config --libs gnutls)

CFLAGS = -O0 -g -Wall -DVERSION=\"$(version)\" $(inc)
LDFLAGS = $(libs)
