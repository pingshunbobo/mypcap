#include <stdio.h>
#include <arpa/inet.h>

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    tcp_seq th_seq;        /* sequence number */
    tcp_seq th_ack;        /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;        /* window */
    u_short th_sum;        /* checksum */
    u_short th_urp;        /* urgent pointer */
};

int tcp_packet(u_char *tcp_packet)
{
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */
    tcp = (struct sniff_tcp*)(tcp_packet);
    u_int size_tcp;

    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(tcp_packet + size_tcp);

    return 0;
}
