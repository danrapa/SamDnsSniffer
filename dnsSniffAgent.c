#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHERNET_HEADER_SIZE 14
#define DNS_PORT 53

/*
 *   12 Bytes of DNS header:
 *
 * 0          15|16        31
 * --------------------------
 * | Id         | Flags     |
 * --------------------------
 * | Questions  | Answers   |
 * --------------------------
 * |  Auth_RRs  | Add_RRs   |
 * --------------------------
 */
typedef struct dnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authRrs;
    uint16_t addRrs;
} dnsHeader;

/*  DNS record types:
 *  TYPE_A      - RDATA is a 4-byte IPv4 address
 *  TYPE_AAAA   - RDATA is a 16-byte IPv6 address
 *  TYPE_CNAME  - RDATA is a domain name
 */
#define TYPE_A     1
#define TYPE_AAAA  28
#define TYPE_CNAME 5


void parseDnsName(const unsigned char *pkt,
                  const unsigned char *ptr,
                  char *output, int pktLen) {
    int offset, i = 0, skip = 0, len, j;
    const unsigned char *base = ptr;

    while(*ptr && (i < pktLen - 1)) {
        if ((*ptr & 0xC0) == 0xC0) {
            if (!skip)
                base = ptr + 2;
            offset = ((*ptr & 0x3F) << 8) | *(ptr + 1);
            ptr = packet + offset;
            skip = 1;
        } else {
            len = *ptr++;
            for (j = 0; j < len && i < pktLen - 1; j++)
                output[i++] = *ptr++;
            output[i++] = '.';
        }
    }
    if (i > 0)
        output[i-1] = '\0';
    else
        output[0] = '\0';

    if (!skip)
        base = ptr + 1;
}