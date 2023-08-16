SOURCES =  main.c  mdm.c tty2tcp.c tftp.c  usb_linux.c sony.c ftp.c 

CFLAGS += -Wall -Werror -O1 -Wno-error=unused-but-set-variable#-s
LDFLAGS += -lpthread -ldl -lrt

ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

linux: clean
	${CC} $(CFLAGS) $(SOURCES) -o QLog ${LDFLAGS} 

clean:
	rm -rf usbdevices *.exe *.dSYM *.obj *.exp .*o *.lib *~ libs QLog  out
