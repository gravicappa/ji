exe = ji
CFLAGS += ${pkg-config --cflags iksemel}
LDFLAGS += -lutil ${shell pkg-config --libs iksemel}
destdir=/usr/local
src = ji.c

all: ${exe}

install:
	install -m 755 ${exe} ${destdir}/bin

${exe} : ${src}
	${CC} ${CFLAGS} $< ${LDFLAGS} -o $@ 
