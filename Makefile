CC=gcc
EXECUTABLE=emdns

all: main
	
main: emdns.o main.o
	$(CC) *.c -o $(EXECUTABLE)

clean:
	rm *.o $(EXECUTABLE)