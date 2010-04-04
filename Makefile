exe = ji
CFLAGS += -O0 -g
CFLAGS += ${pkg-config --cflags iksemel}
LDFLAGS += -lutil ${shell pkg-config --libs iksemel}
destdir=/usr/local
src = ji.c

all: ${exe}

install:
	install -m 755 ${exe} ${destdir}/bin

${exe} : ${src}
	${CC} ${CFLAGS} $< ${LDFLAGS} -o $@ 

clean:
	-rm ${exe} 2>/dev/null
