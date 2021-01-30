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
./emdns < sample.zone
```

Default port is 5959 UDP. 

You can send a query using `dig` as follows:
```
dig @127.0.0.1 -p 5959 subdomain.sample.com
```

If you use the sample zone file this would return:
```
subdomain.sample.com.   0       IN      CNAME   mail2.sample.com.
mail2.sample.com.       0       IN      CNAME   mail.sample.com.
mail.sample.com.        0       IN      A       192.0.2.3
``` 

## Compile options
`EMDNS_SUPPORT_ALL_CLASSES` By default only IN (Internet) class is used. If you want to enable all classes, you can do it by setting the `EMDNS_SUPPORT_ALL_CLASSES` define when compiling:
```
make CFLAGS=-DEMDNS_SUPPORT_ALL_CLASSES
```
Keep in mind that this changes the interface and adds an additional parameter (the class) to some of the functions.

`EMDNS_DISABLE_ALIAS_RESOLVING` By default aliases (CNAME records) are automatically resolved and included in the response. This results in less requests, but slightly increased memory requirement for the response buffer. You can disable the automatic alias resolving by setting the `EMDNS_SUPPORT_ALL_CLASSES` define:
```
make CFLAGS=-DEMDNS_DISABLE_ALIAS_RESOLVING
```

`EMDNS_ENABLE_LOGGING` If you want to enable logging of additional information on stdout, set the `EMDNS_ENABLE_LOGGING` define:
```
make CFLAGS=-DEMDNS_ENABLE_LOGGING
```

## Stability and open issues
This software is still under development, therefore it is not considered stable and might not function properly. If you have problems, feel free to open an issue.
