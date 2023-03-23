#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap/pcap.h>
#include"structures.h"
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SNAPLEN 1000 // snaplen is the maxiumum number of bytes to be captured
#define TOMS 3000  // timeout in ms (milli seconds)
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header pointer of type sniff_ethernet */
const struct sniff_ip *ip; /* The IP header pointer of type struct sniff_ip */
const struct sniff_tcp *tcp; /* The TCP header pointer of type struct sniff_tcp */
const char *payload; /* Packet payload pointer of type char */

__u_int size_ip;
__u_int size_tcp;

typedef unsigned char u_char;


struct Packet {
    int valie;
    char *name;
}Player = {1,"c"};

void get_packet(__u_char *args,const struct pcap_pkthdr *header,const __u_char *packet){
    // gets packet
    static int packet_counter = 0;

    ethernet = (struct sniff_ethernet*)(packet); // typecasting packet pointer of type u_char to type struct sniff_ethernet   
    printf("%s\n",ethernet->ether_dhost);  
    // ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); // typecasting packet pointer to type struct sniff_ip 
    // size_ip = IP_HL(ip)*4; //
    // if (size_ip < 20) {
    //     printf("   * Invalid IP header length: %u bytes\n", size_ip);
    //     return;
    // }
    // tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip); // typecasting packet address + bytes of ethernet and ip to type struct sniff_tcp
    // size_tcp = TH_OFF(tcp)*4;
    // if (size_tcp < 20) {
    //     printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    //     return;
    // }
    // payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp); // type packet address + byte ethernet bytes ip and tcp headers to type u_char (unsigned char)   

    // packet_counter++; // static memory value, stored in segmented memory, incremenred on each incoming packet

    }


int main(){
    printf("%s\n","Packet sniffer with libpcap");

    pcap_if_t *interface; // pointer of type struct pcap_if 

    const char *dev; // dev pointer of type char (will store interface which packets are arriving)
    const char *inter = "eth0"; // const char poiner to eth9 interface string literal
    const char *inter1 = "xl1"; // const char pointer to xl1 interface string literal
    const char *inter2 = "wlp1s0"; // const char pointer to wlan interface string literals
    const char *inter3 = "wlan0";
    const char *inter4 = "wlp2s0"; // cont char pointer to wlan interface string literals
    char err_buffer[PCAP_ERRBUF_SIZE]; // error buffer string of length 256
    char h[] = "Hello";
    int devStatus;
    pcap_t *ppcap; // pointer of type pcap_t (struct pcap)
    struct bpf_program bpf_p; // struct of type struct bpf_program which stores filter rules within members
    const char * rules = "port 80"; // const char pointer of filter rule string literal 
    bpf_u_int32 net; // ip of sniffing device ip4 32 bit
    bpf_u_int32 mask; // network mask to identify host and 
    struct pcap_pkthdr pkt_header; // struct of type struct pcap_pkthdr 
    const __u_char *ppktheader_char; // pointer of type u_char (un signed char) which stores returned packet after sniffing
    int pktloop; // pkt loop return value store

    // dev = "Test"; // string literal

    devStatus = pcap_findalldevs(&interface,err_buffer); // returns character pointer of the network interface

    if(devStatus==PCAP_ERROR){
        // triggered if no network devices are found
        printf("Cannot find any deviced\n");
        return 1; // returns 1 on failure
    }

    printf("Number of devices are %d\n",devStatus);

    ppcap = pcap_open_live(inter4,SNAPLEN,TOMS,5,err_buffer); // pcap_open_live creates a packet capture session and returns pointer of type pcap_t using wko2s0 device stored as string literal. Returns pointer of type pcap_t(typedef)

    if(ppcap==NULL){
        printf("Could not open device %s\n",err_buffer);
        return 1;
    }

    printf("SUCCESFUL\n");
    // printf("%s\n",ppcap)

    if(pcap_datalink(ppcap) !=DLT_EN10MB){  
        // triggered if device does not returns ethernet headers (link) within packets
        printf("Packets do not contains ethernet headers");
        return 1;
    }

    //compile and filtering

    if(pcap_lookupnet(inter4,&net,&mask,err_buffer)==-1){
        // triggered if lookupnet returns -1 indicating failure
        printf("Could not find ipv4 address of sniffing device");
        return -1;
    }

    printf("%d\n",net);
    printf("%d\n",mask);

    if(pcap_compile(ppcap,&bpf_p,rules,1,net)==-1){
        // triggered if packet capture could not compile filter rules
        printf("Could not compile filter rules");
        return -1;
    }

    if(pcap_setfilter(ppcap,&bpf_p)==-1){
        // triggered if filter could not be set
        printf("Could not set filter");
        return -1;
    }

    //capturing single packet

    // ppktheader_char = pcap_next(ppcap,&pkt_header); // returns single packet 

    // printf("%s\n",ppktheader_char);

    // printf("Packet leng is %ld Bytes\n",pkt_header.ts.tv_sec);  

    // capturing packet within loop

    // void pkt_capture_handler(__u_int *args, const struct pcap_pkthdr *header,const __u_char *packet){
    //     // packet capture handler which takes pktheader pointer 
    // }

    pcap_loop(ppcap,10,get_packet,NULL);







    return 0;
}