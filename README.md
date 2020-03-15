![Build on Linux](https://github.com/mtsarev/emdns/workflows/Build%20on%20Linux/badge.svg)

Simple authoritative DNS server, suitable for embedded systems.

## Building emdns
Current implementation can be compiled under Linux/Unix using `make`:
```
make
```

or manually:
```
gcc *.c -o emdns
```

## Running emdns
The compiled executable can be run directly:
```
./emdns
```

Default port is 5959 UDP.

## Compile options
By default only IN (Internet) class is used. If you want to enable all classes, you can do it by setting the `EMDNS_SUPPORT_ALL_CLASSES` define when compiling:
```
make CFLAGS=-DEMDNS_SUPPORT_ALL_CLASSES
```
Keep in mind that this changes the interface and adds an additional parameter (the class) to some of the functions.

PS. This software is still under development, therefore it is not considered stable.
