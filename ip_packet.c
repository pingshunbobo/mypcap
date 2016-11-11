#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "packet_count.h"

#ifndef  IP_HEADER
#define IP_HEADER

/* IP header */
struct sniff_ip {
    u_char ip_vhl;        /* version << 4 | header length >> 2 */
    u_char ip_tos;        /* type of service */
    u_short ip_len;        /* total length */
    u_short ip_id;        /* identification */
    u_short ip_off;        /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff    /* mask for fragmenting bits */
    u_char ip_ttl;        /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;        /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)        (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

#endif

void ip_packet(u_char *ip_packet, struct index_table *counter){

    const struct sniff_ip *ip; /* The IP header */

    u_int size_ip;

    ip = (struct sniff_ip*)(ip_packet);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf(" * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    if( ip->ip_vhl >> 4 != 0x04){
	printf("This packet version is %x not ipv4\n",ip->ip_vhl >> 4);
        return;
    }

//    printf("src: %s\t",inet_ntoa(ip->ip_src));
//    printf("dst: %s",inet_ntoa(ip->ip_dst));

    //ICMP（1）、IGMP（2） 、TCP（6）、UDP（17）
    switch(ip->ip_p){
        case(0x01):
            icmp_packet(ip_packet + size_ip);
            break;
        case(0x02):
//            printf("\tIGMP\n");
            break;
        case(0x06):
            tcp_packet(ip_packet + size_ip);
            break;
        case(0x11):
            udp_packet(ip_packet + size_ip);
            break;
    }
    add_count(ip,counter);
//    printf("\n");
    return;
}
