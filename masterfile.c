/*
 * Parsing of master files based on rfc1035.
 */
#include "masterfile.h"
#include "stdlib.h"
#include "string.h"
#include "emdns.h"

#define EMDNS_PARSER_TEMPBUF 128

typedef enum {
    INIT,
    COMMAND,
    ORIGIN,
    RECORD,
    TTL
} parsing_state_t;

static parsing_state_t state = INIT;
static FILE* stream;
static const char DOLLAR = '$';
static const char SEMICOLON = ';';
static const char QUOTE = '"';
static const char SPACE = ' ';
static const char TAB = '\t';
static const char NEWLINE = '\n';
static char buf[EMDNS_PARSER_TEMPBUF];
static char domain_zone[64];
static char domain[64];
static char response[128];
static dns_class_t class;
static dns_record_t type;
static char* p_buf = buf;
static char c; // current character
static uint32_t default_ttl = 0;

/**
 * Declaration of all helper functions.
 */
static void nextchar();
static void keep();
static char is(char* string);
static char is_numeric();
static void reset();
static char is_end_token();
static void read_token(char ignore_white);
static void read_token_eol(char ignore_quotes);
static char expect(char expected);
static void store_token(char* dest);
static void ignore_whitespace();
static dns_class_t is_class();
static dns_record_t is_type();
static char is_relative(char* str);

/**
 * Definition of all helper functions.
 */
static void nextchar() {
    static char in_parentheses = 0;
    static char in_comment = 0;
    
    while(1){
        c = getc(stream);

        if(in_comment && c != NEWLINE){
            continue;
        }
        
        if (c == '(') {
            if (!in_parentheses) {
                in_parentheses = 1;
                continue;
            }
        }
        else if (c == ')') {
            if (in_parentheses) {
                in_parentheses = 0;
                continue;
            }
        }
        else if (c == SEMICOLON) {
            in_comment = 1;
            continue;
        }
        else if(c == NEWLINE){
            in_comment = 0;
            if(in_parentheses){
                continue;
            }
        }

        return;
    }
}

static void keep() {
    *p_buf = c;
    p_buf++;
    // TODO check boundary
}

static void keep_char(char _c) {
    *p_buf = _c;
    p_buf++;
}

static char is(char* string) {
    return strncmp(buf, string, EMDNS_PARSER_TEMPBUF) == 0;
}

static char is_numeric() {
    char* p = buf;
    while (*p != '\0') {
        if ((*p < '0') || (*p > '9')) {
            return 0;
        }
        p++;
    }
    // it can be numeric, only if it is at least one character
    return (buf != '\0');
}

static void reset() {
    *p_buf = '\0';
    p_buf = buf;
}

static char is_end_token() {
    return c == TAB || c == SPACE ||
        c == NEWLINE || c == EOF ||
        c == SEMICOLON;
}

static void read_token(char ignore_white) {
    if (ignore_white) {
        ignore_whitespace();
    }
    while (1) {
        if (!is_end_token()) {
            keep();
        }
        else {
            reset();
            return;
        }
        nextchar();
    }
}

static void read_tokens(uint8_t count) {
    ignore_whitespace();
    while (1) {
        if (!is_end_token()) {
            keep();
        }
        else {
            count--;
            if(count > 0){
                keep_char(SPACE);
                ignore_whitespace();
                keep();
            }
            else{
                reset();
                return;
            }
        }
        nextchar();
    }
}

static void read_token_eol(char ignore_quotes) {
    char in_quote = 0;
    ignore_whitespace();
    if(ignore_quotes && c == QUOTE){
        in_quote = 1;
        nextchar();
    }
    while (1) {
        char quote_terminates_token = (ignore_quotes && in_quote && c == QUOTE);
        if (c != NEWLINE && c != SEMICOLON && c != EOF && !quote_terminates_token) {
            keep();
        }
        else {
            if(ignore_quotes && in_quote){
                nextchar();
                expect(NEWLINE);
            }
            reset();
            return;
        }
        nextchar();
    }
}

static char expect(char expected) {
    ignore_whitespace();
    return c == expected;
}

static void store_token(char* dest) {
    strcpy(dest, buf);
}

static void ignore_whitespace() {
    while (c == SPACE || c == TAB) {
        nextchar();
    }
}

static dns_class_t is_class() {
    if (is("IN")) {
        return ClassIN;
    }
#ifdef EMDNS_SUPPORT_ALL_CLASSES                  
    else if (is("CS")) {
        return ClassCS;
    }
    else if (is("CH")) {
        return ClassCH;
    }
    else if (is("HS")) {
        return ClassHS;
    }
#endif                
    else {
        return 0;
    }
}

static dns_record_t is_type() {
    if (is("A")) {
        return RecordA;
    }
    else if (is("NS")) {
        return RecordNS;
    }
    else if (is("CNAME")) {
        return RecordCNAME;
    }
    else if (is("SOA")) {
        return RecordSOA;
    }
    else if (is("PTR")) {
        return RecordPTR;
    }
    else if (is("MX")) {
        return RecordMX;
    }
    else if (is("TXT")) {
        return RecordTXT;
    }
    else {
        return 0;
    }
}

static char is_relative(char* str){
    while( *str ){ str++; }
    str--;
    return *str != '.'; 
}

static char to_absolute(char* str){
    while( *str ){ str++; }
    *str = '.';
    strcpy(++str, domain_zone);
}

uint16_t masterfile_parse(FILE* s) {
    stream = s;
    nextchar();
    reset();
    uint16_t records_added = 0;


    while (c != EOF) {
        switch (state) {
            case INIT:
                ignore_whitespace();
                if (c == DOLLAR) {
                    state = COMMAND;
                }
                else if (!is_end_token()) {
                    keep();
                    state = RECORD;
                }
                break;

            case COMMAND:
                read_token(0);
                if (is("ORIGIN")) {
                    state = ORIGIN;
                }
                else if (is("INCLUDE")) {
                    return -1; // not supported
                }
                else if(is("TTL")){
                    state = TTL;
                }
                else {
                    return -1; // unknown
                }
                break;

            case ORIGIN:
                read_token(1);
                store_token(domain_zone);
                if (!expect(NEWLINE)) {
                    return -1; // unexpected token
                }
                else {
                    state = INIT;
                }
                break;
                
            case TTL:
                read_token(1);
                if(is_numeric()){
                    default_ttl = atoi(buf);
                }
                else{
                    return -1;
                }
                    
                if (!expect(NEWLINE)) {
                    return -1; // unexpected token
                }
                else {
                    state = INIT;
                }
                break;

            case RECORD:
            {
                char has_ttl = 0;
                char has_class = 1;
                char has_name = 1;

                // name
                read_token(0);
                if (is("@")) {
                    // use origin domain
                    strcpy(domain, domain_zone);
                }
                else if(is_class() || is_type()){
                    // empty string for domain - use last one
                    has_name = 0;
                }
                else {
                    // domain was read
                    store_token(domain);
                    if(is_relative(domain)){
                        to_absolute(domain);
                    }
                }

                // (optional) TTL
                if(has_name){
                    read_token(1);
                }
                uint32_t ttl = default_ttl;

                if (is_numeric()) {
                    ttl = atoi(buf);
                    read_token(1);
                    has_ttl = 1;
                }

                // (optional) class
                class = is_class();
                if(!class){
                    has_class = 0;
                }

                // type
                if (has_class || has_ttl) {
                    read_token(1);
                }

                type = is_type();
                
                // rdata
                if(type == RecordA || 
                   type == RecordNS || 
                   type == RecordCNAME || 
                   type == RecordPTR){ 
                    read_tokens(1); 
                }
                else if(type == RecordMX){ 
                    read_tokens(2);
                }
                else if(type == RecordSOA){
                    read_tokens(7);
                }
                else if(type == RecordTXT){
                    read_token_eol(1);
                }
                
                store_token(response);
                
                if(((type == RecordNS) ||
                    (type == RecordCNAME) ||
                    (type == RecordMX))
                    && is_relative(response)){
                    to_absolute(response);
                }

                // pass to emdns core
#ifdef EMDNS_SUPPORT_ALL_CLASSES                     
                emdns_add_record(domain, type, class, response, ttl);
#else
                emdns_add_record(domain, type, response, ttl);
#endif                
                records_added++;

                if (!expect(NEWLINE)) {
                    if (c == EOF) {
                        // all good - continue
                    }
                    else {
                        return -1; // unexpected token
                    }
                }
                else {
                    state = INIT;
                }
            }
                break;
        }

        nextchar();
    }

    return records_added;
}