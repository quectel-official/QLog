SOURCES =  main.c mdm.c tty2tcp.c tftp.c usb_linux.c ftp.c 

CFLAGS += -Wall -Werror -O1 -Wno-error=unused-but-set-variable
LDFLAGS += -lpthread -ldl -lrt

ifeq ($(CC),cc)
CC=${CROSS_COMPILE}gcc
endif

linux: clean
	${CC} $(CFLAGS) $(SOURCES) -o QLog ${LDFLAGS} 

clean:
	rm -rf   *.o  *~  QLog  
