#ifndef EMDNS_H
#define EMDNS_H

#include "emsettings.h"
#include "dns.h"

#ifdef EMDNS_SUPPORT_ALL_CLASSES
/**
 * Add a record to the DNS zone.
 * 
 * @param domain domain name
 * @param record_type record type
 * @param record_class record class
 * @param response response to return
 * @param ttl time to live in seconds
 * @return 0 = success, everything else is an error code
 */
int emdns_add_record(char* domain, dns_record_t record_type, dns_class_t record_class, char* response, uint32_t ttl);
#else
/**
 * Add a record to the DNS zone.
 * 
 * @param domain domain name
 * @param record_type record type
 * @param response response to return
 * @param ttl time to live in seconds
 * @return 0 = success, everything else is an error code
 */
int emdns_add_record(char* domain, dns_record_t record_type, char* response, uint32_t ttl);
#endif

#ifdef EMDNS_SUPPORT_ALL_CLASSES
/**
 * Remove records from the DNS zone. Will remove all entries of this type. 
 * 
 * @param domain domain name
 * @param record_type the record type
 * @param record_class record class
 * @return returns the number of entries removed
 */
int emdns_remove_record(char* domain, dns_record_t record_type, dns_class_t record_class);
#else
/**
 * Remove records from the DNS zone. Will remove all entries of this type. 
 * 
 * @param domain domain name
 * @param record_type the record type
 * @return returns the number of entries removed
 */
int emdns_remove_record(char* domain, dns_record_t record_type);
#endif

/**
 * Resolve a DNS entry based on the DNS query in request_buffer. Pass the query
 * in a row format as it is received via the network without any modifications.
 * This function will return the answer of the DNS query in answer_buffer, its
 * length will be answer_len. The answer can be sent directly via the network.
 * 
 * @param request_buffer the request as received via the network
 * @param answer_buffer response will be prepared here
 * @param answer_len this is the real size of the response
 */
void emdns_resolve_raw(char* request_buffer, char** answer_buffer, uint16_t* answer_len);

#endif /* EMDNS_H */

