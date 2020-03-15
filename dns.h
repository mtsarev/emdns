#ifndef DNS_H
#define DNS_H

#include "stdint.h"

/**
 * DNS packet header.
 */
typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}
dns_header_t;

/**
 * DNS record types.
 */
typedef enum {
    RecordA = 1,
    RecordNS = 2,
    RecordCNAME = 5,
    RecordSOA = 6,
    RecordPTR = 12,
    RecordMX = 15,
    RecordTXT = 16
} dns_record_t;

/**
 * DNS record classes.
 */
typedef enum {
    ClassIN = 1,    ///< Internet
    ClassCS = 2,    ///< CSNET (obsolete)
    ClassCH = 3,    ///< Chaos (obsolete)
    ClassHS = 4,    ///< Hesoid (obsolete)
    ClassANY = 255  ///< for requests only
} dns_class_t;

/**
 * Flags used in DNS packet header.
 */
typedef enum {
    FlagQR = 0x8000,
    FlagAA = 0x0400,
    FlagTC = 0x0200,
    FlagRD = 0x0100,
    FlagRA = 0x0080,
    FlagOpQuery = 0x0000,
    FlagOpInvQuery = 0x0800,
    FlagOpStatus = 0x1000,
    FlagNoError = 0x0000,
    FlagErrFormat = 0x0001,
    FlagErrServerFail = 0x0002,
    FlagErrName = 0x0003,
    FlagErrNotImpl = 0x0004,
    FlagErrRefused = 0x0005
} dns_flags_t;

#endif /* DNS_H */

