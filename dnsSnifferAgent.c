#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/ip.h>     // for struct iphdr
#include <netinet/udp.h>    // for struct udphdr
#include <netinet/ether.h>  // for struct ethhdr
#include <netinet/tcp.h>    // for struct tcphdr
#include <netinet/ip6.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <time.h>


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 1. shouldnt the threads join?                                                                        ////////////////////////////////////////////////
// 2. why the conditions are ordered as they are? ipv6 -> eth (or return) -> ipv4?                      ////////////////////////////////////////////////
// 3. is this code optimal in terms of the coding style (duplicated code?)                              ////////////////////////////////////////////////
// 4. is this coe thread safe?                                                                          ////////////////////////////////////////////////
// 5. is the enqueue/dequque are used correctly?                                                        ////////////////////////////////////////////////
// 6. is it blocking?                                                                                   ////////////////////////////////////////////////
// 7. does the epoll mechanism used correctly?                                                          ////////////////////////////////////////////////
// 8. is it possible to add the ZERO COPY that is commented out (optional)                              ////////////////////////////////////////////////
// 9. how is the performance of the code (runtime complexity and space complexity), can it be improved? ////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#define BUFFER_SIZE     65536
#define DNS_PORT        53
#define DNS_PORT_BE     (DNS_PORT << 8)
#define MAX_EVENTS      10
#define QUEUE_SIZE      1024
#define WORKER_COUNT    4

// A packet slot in our ring buffer
typedef struct {
    size_t len;
    u_char data[BUFFER_SIZE];
} packet_t;

// --------------------------------------------------------------------------
// 1) Make the BPF code array and its sock_fprog global
// --------------------------------------------------------------------------
static struct sock_filter dns_bpf_code[] = {
    /* 0: load EtherType */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 12),

    /* 1–2: if ETH_P_IP (0x0800), jump to #4; else fall through */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP,   0, 4),
    /* 3: if ETH_P_IPV6 (0x86DD), jump to #7; else drop */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 7),
    /* 4: drop everything else */
    BPF_STMT(BPF_RET  | BPF_K,     0),

    /* ---- IPv4 path (instr #5 on) ---- */
    /* 5: load IP protocol */
    BPF_STMT(BPF_LD   | BPF_B   | BPF_ABS, 14+9),
    /* 6: if UDP, jump to #10; if TCP, jump to #8; else drop */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 2),
    BPF_STMT(BPF_RET  | BPF_K,     0),

    /* ---- TCP over IPv4: instr #8 on ---- */
    /* 8: load TCP src port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+20),
    /* 9: if port==53 jump to #12; else load dst port */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 2, 0),
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+22),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 0, 1),
    BPF_STMT(BPF_RET  | BPF_K,     0),
    /* accept */
    BPF_STMT(BPF_RET  | BPF_K,     (u_int)-1),

    /* ---- UDP over IPv4: instr #12 on ---- */
    /* 12: load UDP src port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+20),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 2, 0),
    /* 14: load UDP dst port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+22),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 0, 1),
    BPF_STMT(BPF_RET  | BPF_K,     0),
    /* accept */
    BPF_STMT(BPF_RET  | BPF_K,     (u_int)-1),

    /* ---- IPv6 path (instr #17 on) ---- */
    /* 17: load IPv6 Next Header */
    BPF_STMT(BPF_LD   | BPF_B   | BPF_ABS, 14+6),
    /* 18: if UDP, jump to #22; if TCP, jump to #20; else drop */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 2),
    BPF_STMT(BPF_RET  | BPF_K,     0),

    /* ---- TCP over IPv6: instr #20 on ---- */
    /* 20: load TCP src port (after 40-byte IPv6 header) */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+40+0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 2, 0),
    /* 22: load TCP dst port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+40+2),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 0, 1),
    BPF_STMT(BPF_RET  | BPF_K,     0),
    /* accept */
    BPF_STMT(BPF_RET  | BPF_K,     (u_int)-1),

    /* ---- UDP over IPv6: instr #25 on ---- */
    /* 25: load UDP src port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+40+0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 2, 0),
    /* 27: load UDP dst port */
    BPF_STMT(BPF_LD   | BPF_H   | BPF_ABS, 14+40+2),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DNS_PORT_BE, 0, 1),
    BPF_STMT(BPF_RET  | BPF_K,     0),
    /* accept */
    BPF_STMT(BPF_RET  | BPF_K,     (u_int)-1),
};

static struct sock_fprog dns_bpf_prog = {
    .len    = (unsigned short)(sizeof(dns_bpf_code) / sizeof(dns_bpf_code[0])),
    .filter = dns_bpf_code,
};

// --------------------------------------------------------------------------
//  THREAD-SAFE RING BUFFER
//    - Protected by rb_mutex
//    - Single producer (I/O thread) + multiple consumers (worker threads)
// --------------------------------------------------------------------------
static packet_t      rb_queue[QUEUE_SIZE];
static size_t        rb_head = 0;
static size_t        rb_tail = 0;
static pthread_mutex_t rb_mutex = PTHREAD_MUTEX_INITIALIZER;

// --------------------------------------------------------------------------
// 2) Helper to attach that global filter to any socket
// --------------------------------------------------------------------------
void attach_dns_bpf(int sock_fd) {
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER,
                   &dns_bpf_prog, sizeof(dns_bpf_prog)) < 0) {
        perror("SO_ATTACH_FILTER");
        exit(1);
    }
}

/**
 * Enqueue a packet into the ring buffer.
 * If the buffer is full, the packet is dropped.
 */
void enqueue(const packet_t *pkt) {
    pthread_mutex_lock(&rb_mutex);
    size_t next = (rb_tail + 1) % QUEUE_SIZE;
    if (next != rb_head) {
        rb_queue[rb_tail] = *pkt;
        rb_tail = next;
    }

    // else: buffer full → drop packet
    pthread_mutex_unlock(&rb_mutex);
}

/**
 * Dequeue a packet for processing.
 * @return 1 if a packet was returned, 0 if the buffer was empty.
 */
int dequeue(packet_t *out) {
    pthread_mutex_lock(&rb_mutex);
    if (rb_head == rb_tail) {
        // empty
        pthread_mutex_unlock(&rb_mutex);
        return 0;
    }
    *out = rb_queue[rb_head];
    rb_head = (rb_head + 1) % QUEUE_SIZE;
    pthread_mutex_unlock(&rb_mutex);
    return 1;
}

// --------------------------------------------------------------------------
//  DNS NAME PARSER
// --------------------------------------------------------------------------
/**
 * @brief Decode a DNS-style domain name (with compression) from the packet.
 *
 * Walks the length-prefixed labels, follows compression pointers (0xC0xx),
 * protects against loops and overflow, and writes a human-readable name.
 *
 * @param packet     Pointer to the start of the entire IP/Ethernet packet.
 * @param ptr        Pointer to the first length byte of the DNS name.
 * @param output     Buffer to receive the decoded name (e.g. 256 bytes).
 * @param packet_len Total length of the packet[] to prevent overreads.
 * @param max_output Size of output[] to prevent overflow.
 * @return int       Number of bytes consumed from ptr, or -1 on error.
 */
int parse_dns_name(const u_char *packet,
                   const u_char *ptr,
                   char *output,
                   int packet_len,
                   int max_output)
{
    int out_i = 0;           // next write position in output[]
    int jumped = 0;          // set once we follow a compression pointer
    int depth = 0;           // pointer-chain depth (max 16)
    int bytes_consumed = 0;  // total bytes advanced from original ptr
    // quick bounds check
    if (ptr < packet || ptr >= packet + packet_len) {
        return -1;
    }

    // loop until we hit a zero length or run out of space
    while (1) {
        if (ptr >= packet + packet_len || out_i >= max_output - 1) {
            // out of packet or output space
            return -1;
        }

        unsigned char len = *ptr++;

        // if we have not jumped, count this byte
        if (!jumped) {
            bytes_consumed++;
        }

        // zero length = end of name
        if (len == 0) {
            break;
        }

        // compression pointer?  two-byte offset
        if ((len & 0xC0) == 0xC0) {
            if (ptr >= packet + packet_len) {
                return -1;
            }
            int offset = ((len & 0x3F) << 8) | *ptr++;
            if (offset < 0 || offset >= packet_len) {
                return -1;
            }
            if (!jumped) {
                bytes_consumed += 1;  // we already counted the first byte
            }
            ptr = packet + offset;
            jumped = 1;
            if (++depth > 16) {
                // too many jumps → malformed
                return -1;
            }
            continue;
        }

        // normal label of length 'len'
        if (len > 63 || ptr + len > packet + packet_len) {
            // label too long or runs past packet
            return -1;
        }
        if (out_i + len + 1 >= max_output) {
            // not enough room in output[]
            return -1;
        }

        // copy the label bytes
        for (int j = 0; j < len; j++) {
            output[out_i++] = *ptr++;
            if (!jumped) {
                bytes_consumed++;
            }
        }
        // add a dot after each label
        output[out_i++] = '.';
    }

    // if we added any labels, replace trailing dot with NUL
    if (out_i > 0) {
        output[out_i - 1] = '\0';
    } else {
        // empty name (root)
        output[0] = '\0';
    }

    // if we never followed a pointer, count the final zero byte
    if (!jumped) {
        bytes_consumed++;
    }

    return bytes_consumed;
}

/**
 * @brief Parse one raw packet buffer, extract & print the DNS question name.
 *
 * Steps:
 *  1) Ensure we have Ethernet + IPv4 headers.
 *  2) Verify IP protocol is UDP or TCP.
 *  3) Skip UDP or TCP header (and 2-byte length for TCP DNS).
 *  4) Check port 53 on source or dest.
 *  5) Verify DNS header: QR-bit=1 (response), ancount>0.
 *  6) Call parse_dns_name(), print the result.
 *
 * @param buffer          Raw packet bytes (Ethernet frame).
 * @param bytes_received  Total length of buffer[].
 */
 void handle_packet(const u_char *buffer, int bytes_received) {
    // 2) Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    u_short eth_proto = ntohs(eth->h_proto);
    const u_char *dns;
    int dns_len;
    pthread_t tid = pthread_self();

     // 1) Need at least Ethernet + minimal IPv4
     if (bytes_received < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
         return;
     // IPv6 support
     if (eth_proto == ETH_P_IPV6) {
         // 2a) IPv6 header
         if (bytes_received < (int)(sizeof(struct ethhdr) + sizeof(struct ip6_hdr)))
             return;

         struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(*eth));
         const u_char *l4 = buffer + sizeof(*eth) + sizeof(*ip6);
         int l4_len = bytes_received - sizeof(*eth) - sizeof(*ip6);

         if (ip6->ip6_nxt == IPPROTO_UDP) {
             // UDP over IPv6
             if (l4_len < (int)sizeof(struct udphdr)) return;

             struct udphdr *udp = (struct udphdr *)l4;
             // port 53 check
             if (ntohs(udp->source) != DNS_PORT && ntohs(udp->dest) != DNS_PORT) return;

             dns      = l4 + sizeof(*udp);
             dns_len  = l4_len - sizeof(*udp);

         } else if (ip6->ip6_nxt == IPPROTO_TCP) {
             // TCP over IPv6
             if (l4_len < (int)sizeof(struct tcphdr)) return;
             struct tcphdr *tcp = (struct tcphdr *)l4;
             int tcp_hdr_len = tcp->doff * 4;
             if (l4_len < tcp_hdr_len + 2) return;  // need 2-byte length prefix

             // port 53 check
             if (ntohs(tcp->source) != DNS_PORT && ntohs(tcp->dest) != DNS_PORT) return;

             // skip 2-byte length field in TCP-based DNS
             dns      = l4 + tcp_hdr_len + 2;
             dns_len  = l4_len - tcp_hdr_len - 2;

         } else return;

         // 6) Need at least DNS header
         if (dns_len < 12) return;
         // 7) DNS header checks
         //    QR-flag = 1 → response
         if ((dns[2] & 0x80) == 0) return;
         //    Answer count > 0
         uint16_t ancount = ntohs(*(uint16_t *)(dns + 6));
         if (ancount == 0) return;
         // 8) Parse the question name at offset 12
         char domain[256];
         int consumed = parse_dns_name(buffer,
                                       dns + 12,
                                       domain,
                                       bytes_received,
                                       sizeof(domain));

         if (consumed < 0) return; // parse error
         // 9) Print result
         printf("IPV6 | thread ID = %lu, Domain: %s\n", (unsigned long)tid, domain);
         return;
     } // end IPv6

     // TODO ==> Wy this condition? why here and not first?
     // 2) skip non-IPv4
     if (eth_proto != ETH_P_IP) return; // skip non-IPv4 frames

     // 3) IPv4 header
     struct iphdr *ip = (struct iphdr *)(buffer + sizeof(*eth));
     if (ip->version != 4) return;

     int ip_hdr_len = ip->ihl * 4;
     if (bytes_received < (int)(sizeof(*eth) + ip_hdr_len)) return;

     // 4) Must be UDP or TCP
     const u_char *l4 = buffer + sizeof(*eth) + ip_hdr_len;
     int l4_len = bytes_received - sizeof(*eth) - ip_hdr_len;

     if (ip->protocol == IPPROTO_UDP) {
         // 5a) UDP header
         if (l4_len < (int)sizeof(struct udphdr)) return;
         struct udphdr *udp = (struct udphdr *)l4;

         // port 53 check
         if (ntohs(udp->source) != DNS_PORT && ntohs(udp->dest) != DNS_PORT) {
             return;
         }

         dns      = l4 + sizeof(*udp);
         dns_len  = l4_len - sizeof(*udp);

     } else if (ip->protocol == IPPROTO_TCP) {
         // 5b) TCP header
         if (l4_len < (int)sizeof(struct tcphdr)) return;
         struct tcphdr *tcp = (struct tcphdr *)l4;
         int tcp_hdr_len = tcp->doff * 4;
         if (l4_len < tcp_hdr_len + 2) return;  // need 2-byte length prefix

         // port 53 check
         if (ntohs(tcp->source) != DNS_PORT && ntohs(tcp->dest) != DNS_PORT) {
             return;
         }

         // skip 2-byte length field in TCP-based DNS
         dns      = l4 + tcp_hdr_len + 2;
         dns_len  = l4_len - tcp_hdr_len - 2;
         printf("DAN DAN | ipv4\n");
     } else return;
     // 6) Need at least DNS header
     if (dns_len < 12) return;

     // 7) DNS header checks
     //    QR-flag = 1 → response
     if ((dns[2] & 0x80) == 0) return;

     //    Answer count > 0
     uint16_t ancount = ntohs(*(uint16_t *)(dns + 6));
     if (ancount == 0) return;

     // 8) Parse the question name at offset 12
     char domain[256];
     int consumed = parse_dns_name(buffer,
                                   dns + 12,
                                   domain,
                                   bytes_received,
                                   sizeof(domain));
     if (consumed < 0) return; // parse error
     // 9) Print result
     printf("IPV4 | thread ID = %lu, Domain: %s\n", (unsigned long)tid, domain);
 }


// --------------------------------------------------------------------------
//  WORKER THREADS: dequeue + handle_packet()
// --------------------------------------------------------------------------
void *worker_thread(void *arg) {
    (void)arg;
    packet_t pkt;
    while (1) {
        if (dequeue(&pkt)) {
            handle_packet(pkt.data, pkt.len);
        } else {
            // nothing to do → yield CPU
            usleep(1000);
        }
    }
    return NULL;
}

// --------------------------------------------------------------------------
//  MAIN: socket setup, BPF filter, epoll, PACKET_MMAP, thread launch
// --------------------------------------------------------------------------
int main(void) {
    int raw_sock, epoll_fd;

    // 1) Create AF_PACKET RAW socket
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) { perror("socket"); exit(1); }

    // 2) Increase receive buffer to 4 MiB
    {
        int buf_sz = 4 * 1024 * 1024;
        setsockopt(raw_sock, SOL_SOCKET, SO_RCVBUF,
                   &buf_sz, sizeof(buf_sz));
    }

    // 3) Attach the global DNS‐only BPF filter
    attach_dns_bpf(raw_sock);

    // 4) Make socket non-blocking
    {
        int flags = fcntl(raw_sock, F_GETFL, 0);
        fcntl(raw_sock, F_SETFL, flags | O_NONBLOCK);
    }

    // 5) (Optional) Zero-copy via PACKET_MMAP
    // ASK about this!!!
    // {
        // struct tpacket_req req = {
        //     .tp_block_size = 4096,
        //     .tp_block_nr   = 64,
        //     .tp_frame_size = 2048,
        //     .tp_frame_nr   = (4096*64)/2048,
        // };
        // setsockopt(raw_sock, SOL_PACKET, PACKET_RX_RING,
        //            &req, sizeof(req));
        // void *ring = mmap(NULL,
        //                   req.tp_block_size * req.tp_block_nr,
        //                   PROT_READ|PROT_WRITE,
        //                   MAP_SHARED,
        //                   raw_sock, 0);
        // if (ring == MAP_FAILED) {
        //     perror("mmap");
        //     // continue without zero-copy
        // }
    // }

    // 6) Spawn worker threads
    for (int i = 0; i < WORKER_COUNT; i++) {
        pthread_t tid;
        pthread_create(&tid, NULL, worker_thread, NULL);
    }

    // 7) Set up epoll on raw_sock
    epoll_fd = epoll_create1(0);
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data   = { .fd = raw_sock }
    };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_sock, &ev);

    // 8) I/O loop: batch recvfrom() + enqueue()
    struct epoll_event events[MAX_EVENTS];
    u_char stack_buf[BUFFER_SIZE];

    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);

        if (n < 0 && errno != EINTR) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == raw_sock) {
                // read until EAGAIN to batch
                while (1) {
                    int len = recvfrom(raw_sock,
                                        stack_buf,
                                        sizeof(stack_buf),
                                        0, NULL, NULL);
                    if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        perror("recvfrom");
                        break;
                    }
                    packet_t pkt = { .len = len };
                    memcpy(pkt.data, stack_buf, len);
                    enqueue(&pkt);

                }
            }
        }
    }

    close(raw_sock);
    return 0;
}
