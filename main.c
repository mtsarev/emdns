#include "stdio.h"
#include "stdlib.h"
#include "dns.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "string.h"
#include "emsettings.h"
#include "emdns.h"

#define PORT     5959
#define MAXLINE  128 

int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    
    printf("Starting DNS server...\n");
    char buffer[MAXLINE]; 
    
    struct sockaddr_in servaddr, cliaddr; 
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        printf("error opening socket");
        exit(EXIT_FAILURE); 
    }
    
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
    
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT);    
    
    int len, n; 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    len = sizeof(cliaddr);
    
#ifdef EMDNS_SUPPORT_ALL_CLASSES  
#define CLASS ,ClassIN
#else
#define CLASS
#endif
    emdns_add_record("domain.com", RecordSOA CLASS, "ns1.server.com info.domain.com 2019102611 7200 3600 1209600 3600");
    emdns_add_record("domain.com", RecordA CLASS, "12.34.56.78");
    emdns_add_record("78.56.34.12.in-addr.arpa", RecordPTR CLASS, "domain.com");
    emdns_add_record("mail.domain.com", RecordCNAME CLASS, "domain.com");
    emdns_add_record("domain.com", RecordMX CLASS, "10 mail.domain.com");
    emdns_add_record("domain.com", RecordMX CLASS, "20 mail2.domain.com");
    emdns_add_record("domain.com", RecordTXT CLASS, "v=spf1 mx a:mail.domain.com -all");
    emdns_add_record("example.com", RecordA CLASS, "22.33.44.55");
    emdns_add_record("example.com", RecordNS CLASS, "mail.domain.com");
    emdns_add_record("google.com", RecordA CLASS, "8.8.8.8");
    emdns_remove_record("domain.com", RecordMX CLASS);
    
#ifdef EMDNS_SUPPORT_ALL_CLASSES  
    emdns_add_record("google.com", RecordA, ClassHS, "1.2.3.4");
#endif    
    
    while(1){
        n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, ( struct sockaddr *) &cliaddr, 
                    &len); 

        char* answer_buffer;
        uint16_t answer_len;

        emdns_resolve_raw(buffer, &answer_buffer, &answer_len);

        sendto(sockfd, (const char *)answer_buffer, answer_len,  
            MSG_CONFIRM, (const struct sockaddr *) &cliaddr,  len); 
    }
    
    return (EXIT_SUCCESS);
}

