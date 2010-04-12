exe = ji
CFLAGS = -O0 -g -pedantic -Wall ${pkg-config --cflags iksemel}
LDFLAGS = -lutil ${shell pkg-config --libs iksemel}
destdir = /usr/local
bindir = bin
src = ji.c
obj = ji.o

all: ${exe}

install: all
	install -m 755 ${exe} ${destdir}/${bindir}

uninstall: all
	rm ${destdir}/${bindir}/${exe}

${exe} : ${obj}
	${CC} -o $@ $^ ${LDFLAGS} -o $@ 

.c.o:
	${CC} -c ${CFLAGS} $< -o $@

clean:
	-rm ${exe} 2>/dev/null
