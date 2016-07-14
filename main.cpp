#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include "header.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

int main()
{
    char * dev;
    char * net;
    char * mask;

    char errbuf[PCAP_ERRBUF_SIZE]={0,};

    // getting network device name

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("device : %s\n",dev);

    int ret;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    // getting network and mask information from device name.

    ret=pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if(ret==-1){
        printf("%s\n", errbuf);
        exit(1);
    }

    struct in_addr net_addr;

    net_addr.s_addr = netp;     // netp(bpf_u_int32) => net_addr.s_addr(u_int32_t)

    net = inet_ntoa(net_addr);  // net_addr(in_addr structure) => string (network address)

    if(net == NULL)
    {
        perror("No Network Address");
        exit(1);
    }

    printf("NET: %s\n",net);

    struct in_addr mask_addr;

    mask_addr.s_addr = maskp;   // maskp(bpf_u_int32) => mask_addr.s_addr(u_int32_t)

    mask=inet_ntoa(mask_addr);  // mask_addr(in_addr structure) => string (subnet mask address)

    if(mask == NULL)
    {
        perror("No Subnet Mask Address");
        exit(1);
    }
    printf("%s\n",mask);

    pcap_t * packet;    //packet handler

    packet=pcap_open_live(dev, 100, PROMISCUOUS, -1, errbuf);

    // WHEN ERROR WITH HANDLER

    if(packet==NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    int res;

    //capturing packet
    while(1)
    {
        struct pcap_pkthdr * pkt_hdr;   //packet header
        const u_char * pkt_data;        //packet string

        res=pcap_next_ex(packet, &pkt_hdr, &pkt_data);

        if(res==0)
            continue;

        else if(res==-1){
            printf("Error reading the packets: %s\n", pcap_geterr(packet));
            break;
        }

        struct ethhdr * ep = (struct ethhdr *)pkt_data; //synchronizing same memory address to use ethernet header structure(like a template).

        int i;

        //printing source mac address

        printf(" smac : ");

        for(i=0;i<ETH_ALEN-1;i++){
            printf("%.2x:",ep->h_source[i]);
        }
        printf("%.2x\n",ep->h_source[i]);

        //printing destination mac address

        printf(" dmac : ");
        for(i=0;i<ETH_ALEN-1;i++){
            printf("%.2x:",ep->h_dest[i]);
        }
        printf("%.2x\n",ep->h_dest[i]);

        //if ipv4 packet
        if(ntohs(ep->h_proto) == 0x0800){       // network byte order to host byte order

            struct ip4hdr * ipp = (struct ip4hdr *)(pkt_data + sizeof(ethhdr)); //offsetting the size of ethernet header.

            //printing source ip & dest. ip
            printf("  sip : %s\n",inet_ntoa(ipp->ip_src));
            printf("  dip : %s\n",inet_ntoa(ipp->ip_dst));

            //if TCP packet
            if(ipp->ip_p == 0x06){
                struct tcphdr * tcpp = (struct tcphdr *)(pkt_data + sizeof(ethhdr) + sizeof(ip4hdr)); //offsetting the size of ip header.
                //printing source port & dest. port
                printf("sport : %d\n",ntohs(tcpp->th_sport));
                printf("dport : %d\n",ntohs(tcpp->th_dport));
            }
            else
                printf("this is not a tcp packet. byebye\n");
        }
        else{
            printf("this is not a IP packet. byebye\n");
        }
        break;
    }
    return 0;
}
