SOURCES =  main.c mdm.c tty2tcp.c tftp.c usb_linux.c ftp.c sahara-ramdump.c sahara-xprt.c

CFLAGS += -Wall -Werror -O1 -Wno-error=unused-but-set-variable
CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS += -lpthread -ldl -lrt

ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

OUT := qlog
prefix := /usr/local

linux: clean
	${CC} $(CFLAGS) $(SOURCES) -o $(OUT) ${LDFLAGS}

clean:
	rm -rf   *.o  *~  $(OUT)

install:
	mkdir -p $(DESTDIR)$(prefix)/bin
	install $(OUT) $(DESTDIR)$(prefix)/bin
	install -m 755 $(OUT) $(DESTDIR)$(prefix)/bin
