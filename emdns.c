#include "stdlib.h"
#include "string.h"
#include "emdns.h"
#include "stdio.h"
#include "stdlib.h"
#include "arpa/inet.h"

typedef struct emdns_record_t{
    struct emdns_record_t* next;
    dns_record_t record_type;
#ifdef EMDNS_SUPPORT_ALL_CLASSES
    dns_class_t record_class;
#endif    
    char* domain;
    char* response;
    uint32_t ttl;
    uint16_t length;
} emdns_record_t;


static emdns_record_t* records;

static char* _to_dns_string(char* domain);
static uint32_t _to_ip_value(char* ip);

#ifdef EMDNS_SUPPORT_ALL_CLASSES
static emdns_record_t* _find_record(char* domain, dns_record_t record_type, dns_class_t record_class);
#else
static emdns_record_t* _find_record(char* domain, dns_record_t record_type);
#endif

#ifdef EMDNS_SUPPORT_ALL_CLASSES
int emdns_add_record(char* domain, dns_record_t record_type, dns_class_t record_class, char* response, uint32_t ttl) {
#else
int emdns_add_record(char* domain, dns_record_t record_type, char* response, uint32_t ttl) {
#endif    
    
#ifdef EMDNS_ENABLE_LOGGING    
    printf("Added record.\n");
#endif
    
    emdns_record_t* entry = malloc(sizeof (emdns_record_t));
    if (entry != 0) {
        entry->domain = _to_dns_string(domain);
        entry->record_type = record_type;
        entry->ttl = ttl;
#ifdef EMDNS_SUPPORT_ALL_CLASSES
        entry->record_class = record_class;
#endif        
        
        switch(record_type){
            case RecordA:
                entry->length = sizeof(uint32_t);
                entry->response = malloc(entry->length);
                *((uint32_t*)(entry->response)) = htonl(_to_ip_value(response));
                break;

            case RecordCNAME:
            case RecordNS:
            case RecordPTR:
                entry->response = _to_dns_string(response);
                entry->length = strlen(entry->response) + 1;
                break;
                
            case RecordMX:
                entry->length = sizeof(uint16_t) + strlen(response) + 2;
                uint16_t preference = 0;
                entry->response = malloc(entry->length);
                int res = sscanf(response, "%hd %s", &preference, (entry->response + 2));
                
                *((uint16_t*)entry->response) = htons(preference);
                char* dns_str = _to_dns_string(entry->response + 2);
                strcpy(entry->response + 2, dns_str);
                
                entry->length -= (strlen(response) - strlen(dns_str) + 1);
                free(dns_str);
                
                break;
            
            case RecordSOA:
            {
                char* server = malloc(256);
                char* mail = malloc(256);
                uint32_t serial, refresh, retry, expire, minimum;
                
                int res = sscanf(response, "%s %s %d %d %d %d %d", server, mail, &serial, &refresh, &retry, &expire, &minimum);
                entry->length = strlen(server) + 2 + strlen(mail) + 2 + (5 * sizeof(uint32_t));
                entry->response = malloc(entry->length);
                
                char* server_dns = _to_dns_string(server);
                char* mail_dns = _to_dns_string(mail);
                strcpy(entry->response, server_dns);
                strcpy(entry->response + strlen(server_dns) + 1, mail_dns);
                uint8_t* p = entry->response + strlen(server_dns) + strlen(mail_dns) + 2;
                *((uint32_t*)(p + 0)) = htonl(serial);
                *((uint32_t*)(p + 4)) = htonl(refresh);
                *((uint32_t*)(p + 8)) = htonl(retry);
                *((uint32_t*)(p + 12)) = htonl(expire);
                *((uint32_t*)(p + 16)) = htonl(minimum);
                
                entry->length = strlen(server_dns) + 1 + strlen(mail_dns) + 1 + (5 * sizeof(uint32_t));
                
                free(server);
                free(mail);
                free(server_dns);
                free(mail_dns);
            }    
                break;
                
            case RecordTXT:
                entry->length = strlen(response) + 1;
                entry->response = malloc(entry->length);
                *((uint8_t*)entry->response) = strlen(response);
                memcpy(entry->response + 1, response, entry->length);
                break;
        }
        
        entry->next = records;
        records = entry;
        return 0;
    }
    
    return -1;
}

#ifdef EMDNS_SUPPORT_ALL_CLASSES
int emdns_remove_record(char* domain, dns_record_t record_type, dns_class_t record_class) {
#else
int emdns_remove_record(char* domain, dns_record_t record_type) {    
#endif    
    char* dns_string = _to_dns_string(domain);
    emdns_record_t* ptr_record = records;
    emdns_record_t* ptr_prev = 0;
    uint8_t records_removed = 0;
    while (ptr_record != 0) {
        if (ptr_record->record_type == record_type &&
#ifdef EMDNS_SUPPORT_ALL_CLASSES
                ptr_record->record_class == record_class &&
#endif                
                strcmp(ptr_record->domain, dns_string) == 0) {
            if(ptr_record == records){
                records = ptr_record->next;
            }
            else{
                ptr_prev->next = ptr_record->next;
            }
            emdns_record_t* next = ptr_record->next;
            free(ptr_record);
            records_removed++;
            ptr_record = next;
            continue;
        }
        ptr_prev = ptr_record;
        ptr_record = ptr_record->next;
    }
    free(dns_string);
    return records_removed; 
}

static char* _to_dns_string(char* domain) {
    char* dns_string = malloc(2 + strlen(domain));
    char* p_dns_string = dns_string + 1;
    char* p_length_byte = dns_string;
    *p_length_byte = 0;

    while (*domain != '\0') {
        if (*domain != '.') {
            *p_dns_string = *domain;
            (*p_length_byte)++;
        } else {
            p_length_byte = p_dns_string;
            *p_length_byte = 0;
        }
        domain++;
        p_dns_string++;
    }
    *p_dns_string = '\0';
    return dns_string;
}

static uint32_t _to_ip_value(char* ip) {
    uint32_t ip_value = 0x00000000;
    char buf[4];
    char* p_buf = buf;
    char* p_ip = ip;
    uint8_t i = 4;
    while (i--) {
        while (*p_ip != '.' && *p_ip != '\0') {
            *p_buf = *p_ip;
            p_buf++;
            p_ip++;
        }
        (*p_buf) = '\0';
        ip_value = (ip_value << 8) | atoi(buf);
        p_buf = buf;
        p_ip++;
    }
    return ip_value;
}

#ifdef EMDNS_SUPPORT_ALL_CLASSES
static emdns_record_t* _find_record(char* domain, dns_record_t record_type, dns_class_t record_class){
#else
static emdns_record_t* _find_record(char* domain, dns_record_t record_type) {
#endif
    emdns_record_t* ptr_record = records;
    while (ptr_record != 0) {
        if (ptr_record->record_type == record_type &&
#ifdef EMDNS_SUPPORT_ALL_CLASSES
                ptr_record->record_class == record_class &&
#endif                
                strcmp(ptr_record->domain, domain) == 0) {
            return ptr_record;
        }
        ptr_record = ptr_record->next;
    }
    return 0;
}

void emdns_resolve_raw(char* request_buffer, char** response_buffer, uint16_t* answer_len) {

    dns_header_t* decoded = (dns_header_t*) request_buffer;
    decoded->flags = htons(FlagQR | FlagAA); // set response and AA flag

#if EMDNS_ECHO_QUERIES
    // repeat query / not implemented
#endif 

    decoded->qdcount = htons(0);
    decoded->ancount = htons(0);
    decoded->nscount = htons(0);
    decoded->arcount = htons(0);

    // extract
    char* p = (request_buffer + sizeof (dns_header_t));
    uint8_t len = strlen(p);
    dns_record_t type = (dns_record_t) ntohs((*(uint16_t*) (p + len + 1)));
    dns_record_t class = (dns_record_t) ntohs((*(uint16_t*) (p + len + 3)));
#ifdef EMDNS_SUPPORT_ALL_CLASSES
    emdns_record_t* record = _find_record(p, type, class);
#else
    emdns_record_t* record = (class == ClassIN ? _find_record(p, type) : 0);
#endif

    if (record != 0) {
#ifdef EMDNS_ENABLE_LOGGING
        printf("Record found.\n");
#endif
        decoded->ancount = htons(1);

        *((uint16_t*) (p + len + 3)) = htons(ClassIN);
        *((uint32_t*) (p + len + 5)) = htonl(record->ttl);
        *((uint32_t*) (p + len + 9)) = htons(record->length);
        
        memcpy(p + len + 11, record->response, record->length);
        
        *answer_len = sizeof (dns_header_t) + len + 11 + record->length;
        
    } else {

#ifdef EMDNS_ENABLE_LOGGING
        printf("Record not found.\n");
#endif

        decoded->flags = htons(FlagQR | FlagAA | FlagErrName);
        *answer_len = sizeof (dns_header_t);
    }

    *response_buffer = request_buffer;
}