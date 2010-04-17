prefix = /usr/local
bindir = ${prefix}/bin
mandir = ${prefix}/share/man
man1dir = ${mandir}/man1

destdir = 
version = 0.1

INCLUDES = ${shell pkg-config --cflags gnutls} \
           ${shell pkg-config --cflags iksemel}
LIBS = -lutil \
       ${shell pkg-config --libs gnutls} \
       ${shell pkg-config --libs iksemel}

CFLAGS = -O0 -g -pedantic -Wall -DVERSION=\"${version}\" ${INCLUDES}
LDFLAGS = ${LIBS}
