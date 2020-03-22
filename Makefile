CC=gcc
EXECUTABLE=emdns

all: main
	
main: emdns.o main.o masterfile.o
	$(CC) *.c $(CFLAGS) -o $(EXECUTABLE)

clean:
	rm *.o $(EXECUTABLE)