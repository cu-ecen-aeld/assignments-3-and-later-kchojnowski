all: aesdsocket

aesdsocket: aesdsocket.o
	${CC} -Wall -Werror aesdsocket.o -o aesdsocket

aesdsocket.o: aesdsocket.c
	${CC} -Wall -Werror -c aesdsocket.c -o aesdsocket.o

clean:
	rm -f aesdsocket aesdsocket.o
