#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "packet_count.h"

#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};


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
            ip_packet(packet + SIZE_ETHERNET);
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
    return;
}
