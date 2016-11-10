#include <stdio.h>
#include <arpa/inet.h>

/* TCP header */
typedef u_int udp_seq;

struct sniff_udp {
    u_short uh_sport;    /* source port */
    u_short uh_dport;    /* destination port */
    u_short uh_len;
    u_short uh_sum;
};


int udp_packet(u_char *udp_packet)
{
    const struct sniff_udp *udp; /* The UDP header */
    const char *payload; /* Packet payload */
    udp = (struct sniff_udp*)(udp_packet);
    u_int size_udp;

    size_udp = 8;
    printf("\tUDP:sport: %u \t dport: %u",ntohs(udp->uh_sport),ntohs(udp->uh_dport));
    payload = (u_char *)(udp_packet + size_udp);

    return 0;
}
