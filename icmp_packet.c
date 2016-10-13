#include <stdio.h>
#include <arpa/inet.h>

#define SIZE_ICMP 4
/* TCP header */
typedef u_int icmp_seq;

struct sniff_icmp {
    u_char ich_type;    /* source port */
    u_char ich_code;    /* destination port */
    u_short ich_sum;
    u_short ich_id;
    u_short ich_seq;
};

int icmp_packet(u_char *icmp_packet)
{
    const struct sniff_icmp *icmp; /* The UDP header */
    const char *payload; /* Packet payload */
    icmp = (struct sniff_icmp*)(icmp_packet);

    payload = (u_char *)(icmp_packet + SIZE_ICMP);

    return 0;
}
