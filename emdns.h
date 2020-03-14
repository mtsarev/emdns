#ifndef EMDNS_H
#define EMDNS_H

#include "dns.h"

typedef struct emdns_record_t{
    struct emdns_record_t* next;
    dns_record_t record_type;
    char* domain;
    char* response;
    uint16_t length;
} emdns_record_t;

// record management
int emdns_add_record(char* domain, dns_record_t record_type, char* response);

int emdns_remove_record(char* domain, dns_record_t record_type);

// resolve based on un-decoded/raw message
void emdns_resolve_raw(char* request_buffer, char** answer_buffer, uint16_t* answer_len);

#endif /* EMDNS_H */

