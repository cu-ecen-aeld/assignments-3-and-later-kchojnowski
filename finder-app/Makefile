all: writer

writer: writer.o
	${CC} writer.o -o writer

writer.o: writer.c
	${CC} -c writer.c -o writer.o

clean:
	rm -f writer writer.o

