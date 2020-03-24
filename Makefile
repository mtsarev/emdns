CC=gcc
EXECUTABLE=emdns

all: main
	
main: emdns.o main.o masterfile.o
	$(CC) *.c $(CFLAGS) -g -o $(EXECUTABLE)

clean:
	rm *.o $(EXECUTABLE)