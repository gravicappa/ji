exe = ji
man = ji.1
CFLAGS = -O0 -g -pedantic -Wall ${pkg-config --cflags iksemel}
LDFLAGS = -lutil ${shell pkg-config --libs iksemel}
prefix = /usr/local
bindir = ${prefix}/bin
mandir = ${prefix}/share/man
man1dir = ${mandir}/man1
src = ji.c
obj = ji.o

all: ${exe}

install: all
	mkdir -p ${destdir}${bindir}
	mkdir -p ${destdir}${man1dir}
	install -d ${destdir}${bindir} ${destdir}${man1dir}
	install -m 775 ${exe} ${destdir}${bindir}
	install -m 444 ${man} ${destdir}${man1dir}

uninstall: all
	rm ${destdir}${bindir}/${exe}
	rm ${destdir}${man1dir}/${man}

${exe}: ${obj}
	${CC} -o $@ $^ ${LDFLAGS} -o $@ 

.c.o:
	${CC} -c ${CFLAGS} $< -o $@

clean:
	-rm ${obj} ${exe} 2>/dev/null
