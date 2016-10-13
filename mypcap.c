#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

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

void got_packet(u_char *args, const struct pcap_pkthdr *header,
     const u_char *packet);
int main(int argc, char *argv[])
{
    pcap_t *handle;            /* Session handle */
    char *dev;            /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program fp;        /* The compiled filter */
    char filter_exp[] = "";    /* The filter expression */
    bpf_u_int32 mask;        /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;    /* The header that pcap gives us */
    const u_char *packet;        /* The actual packet */

    /*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    */
    dev = argv[1];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
    }
    printf("Device: %s\n", dev);

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
        
    pcap_loop(handle, -1, got_packet, NULL);
    /* And close the session */
    pcap_close(handle);

    return(0);
}
void got_packet(u_char *args,\
    const struct pcap_pkthdr *header,
    const u_char *packet){

    #define HEX_CHAR(ch) ch&0x0000FFFF
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */

    u_int size_ip;

    //    printf("get %d! bytes data:\n",header->len);
    ethernet = (struct sniff_ethernet*)(packet);


    switch(ethernet->ether_type){
        case (0x0008):
            //printf("IP protocal:\t");
            break;
        case (0x0608):
            printf("ARP prtocal:\n");
            return;
        case (0x4c81):
            printf("SNMP prtocal:\n");
            return;
        case (0x3580):
            printf("RARP prtocal:\n");
            return;
        default:
            printf("Know prtocal:\n");
            return;
    }

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf(" * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    if( ip->ip_vhl >> 4 != 0x04){
	printf("This packet version is %x not ipv4\n",ip->ip_vhl >> 4);
        return;
    }

    printf("src: %s\t",inet_ntoa(ip->ip_src));
    printf("dst: %s",inet_ntoa(ip->ip_dst));

    //ICMP（1）、IGMP（2） 、TCP（6）、UDP（17）
    switch(ip->ip_p){
        case(0x01):
            icmp_packet(packet + SIZE_ETHERNET + size_ip);
            break;
        case(0x02):
            printf("\tIGMP\n");
            break;
        case(0x06):
            tcp_packet(packet + SIZE_ETHERNET + size_ip);
            break;
        case(0x11):
            udp_packet(packet + SIZE_ETHERNET + size_ip);
            break;
    }
    printf("\n");
    return;
}
