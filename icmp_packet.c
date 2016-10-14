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

    printf("\t");
    switch(icmp -> ich_type){
        case(3):
            printf("Destination unreachable");
            break;
        case(8):
            printf("ICMP echo request");
            break;
        case(0):
            printf("ICMP echo replay");
            break;
        default:
            printf("ICMP unknow");
    }
    payload = (u_char *)(icmp_packet + SIZE_ICMP);

    return 0;
}
