#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include<time.h>
#include <netinet/udp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
void dump_ethernet(u_int32_t length, const u_char *content);
void dump_ip(u_int32_t length, const u_char *content);
void dump_tcp(u_int32_t length, const u_char *content);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
char *mac_ntoa(u_char *d);
char *ip_ntoa(void *i);
char *ip_ttoa(u_int8_t flag);
char *ip_ftoa(u_int16_t flag);
char *tcp_ftoa(u_int8_t flag);

char whattype[100];
char num[100];
char bound[100];

int number = -1;


int main(int argc, const char * argv[])
{
    printf("%d",argc);
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = NULL;
    
    char *device ;
    char filename[100];
    memset(filename, 0, 100);
    memset(whattype, 0, 100);
    memset(num, 0, 100);
    memset(bound, 0, 100);
    bpf_u_int32 net, mask;
    struct bpf_program fcode;
    device = pcap_lookupdev(errbuf);
    handle = pcap_open_live(device, 65535, 1, 1, errbuf);

    if(strcmp(argv[1],"-r")==0)
    {
        strcpy(filename,argv[2]);
        handle = pcap_open_offline(filename, errbuf);
        if(!handle) {
            fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
            exit(1);
        }
        printf("Open: %s\n", filename);
    }


    if(argc > 3)
    {
        if(strcmp(argv[3],"-u")==0)
        {
            strcpy(whattype,argv[3]);
            printf("only udp\n");
            if(argc > 4)
            {
                strcpy(bound,argv[4]);
            }
        }
        else if(strcmp(argv[3],"-t")==0)
        {
            strcpy(whattype,argv[3]);
            printf("only tcp\n");
            if(argc > 4)
            {
                strcpy(bound,argv[4]);
            }
        }
        else
        {
            strcpy(num,argv[3]);
            number = atoi(num);
            if(argc > 4)
            {
                if(strcmp(argv[4],"-u")==0)
                {
                    strcpy(whattype,argv[4]);
                    printf("only udp\n");
                    if(argc > 5)
                    {
                        strcpy(bound,argv[5]);
                    }
                }
                else if(strcmp(argv[4],"-t")==0)
                {
                    strcpy(whattype,argv[4]);
                    printf("only tcp\n");
                    if(argc > 5)
                    {
                        strcpy(bound,argv[5]);
                        
                    }
                }
            }


        }
    }
    

    //start capture

    pcap_loop(handle, number, pcap_callback, NULL);


    //free
    pcap_close(handle);
    return 0;
}


char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];

    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return str;
}//end mac_ntoa

char *ip_ntoa(void *i) {
    static char str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, i, str, sizeof(str));

    return str;
}//end ip_ntoa

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content)
{
    static int d = 0;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;

    int bound_number =10000000;
    int bound_number2 =0;
    bound_number2 = atoi(bound);
    if(bound_number2 != 0)
    {
        bound_number = bound_number2;
    }
  //  printf("%d\n", header->len);
   // printf("%d\n",bound_number);

    if((header->len) < bound_number )
    {
        if(strcmp(whattype, "-u")==0)
        {
            switch (protocol)
            {
                case IPPROTO_UDP:
                    
                        printf("No. %d\n", ++d);

                        //print header
                        printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
                        printf("\tLength: %d bytes\n", header->len);
                        printf("\tCapture length: %d bytes\n", header->caplen);

                        //dump ethernet
                        dump_ethernet(header->caplen, content);

                        printf("\n");

                case IPPROTO_TCP:
                    break;

                case IPPROTO_ICMP:
                    break;

                default:
                    break;
            }//end switch
        }
        else if(strcmp(whattype, "-t")==0)
        {
            switch (protocol)
            {
                case IPPROTO_UDP:
                    break;

                case IPPROTO_TCP:
                        printf("No. %d\n", ++d);

                        //print header
                        printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
                        printf("\tLength: %d bytes\n", header->len);
                        printf("\tCapture length: %d bytes\n", header->caplen);

                        //dump ethernet
                        dump_ethernet(header->caplen, content);

                        printf("\n");
                    

                case IPPROTO_ICMP:
                    break;

                default:
                    break;
            }//end switch
        }
        else
        {
            printf("No. %d\n", ++d);

            //print header
            printf("\tTime: %s.%.6ld\n", timestr, header->ts.tv_usec);
            printf("\tLength: %d bytes\n", header->len);
            printf("\tCapture length: %d bytes\n", header->caplen);

            //dump ethernet
            dump_ethernet(header->caplen, content);

            printf("\n");

        }
    }
    
    
    

}//end pcap_callback

void dump_ethernet(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {};
    char src_mac_addr[MAC_ADDRSTRLEN] = {};
    u_int16_t type;

    //copy header
    strncpy(dst_mac_addr, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strncpy(src_mac_addr, mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);

    //print
    if(type <= 1500)
        printf("IEEE 802.3 Ethernet Frame:\n");
    else
        printf("Ethernet Frame:\n");

    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Destination MAC Address:                                   %17s|\n", dst_mac_addr);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    printf("| Source MAC Address:                                        %17s|\n", src_mac_addr);
    printf("+-------------------------+-------------------------+-------------------------+\n");
    if (type < 1500)
        printf("| Length:            %5u|\n", type);
    else
        printf("| Ethernet Type:    0x%04x|\n", type);
    printf("+-------------------------+\n");

    switch (type) {
        case ETHERTYPE_ARP:
            printf("Next is ARP\n");
            break;

        case ETHERTYPE_IP:
            dump_ip(length, content);
            break;

        case ETHERTYPE_REVARP:
            printf("Next is RARP\n");
            break;

        case ETHERTYPE_IPV6:
            printf("Next is IPv6\n");
            break;

        default:
            printf("Next is %#06x", type);
            break;
    }//end switch

}//end dump_ethernet

char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;

    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ttoa

char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;

    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ftoa

void dump_udp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);

    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Length:            %5u| Checksum:          %5u|\n", len, checksum);
    printf("+-------------------------+-------------------------+\n");
}//end dump_udp

void dump_ip(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);

    //print
    printf("Protocol: IP\n");
    printf("+-----+------+------------+-------------------------+\n");
    printf("| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           version, header_len, ip_ttoa(tos), total_len);
    printf("+-----+------+------------+-------+-----------------+\n");
    printf("| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           id, ip_ftoa(offset), offset & IP_OFFMASK);
    printf("+------------+------------+-------+-----------------+\n");
    printf("| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",
           ttl, protocol, checksum);
    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n",  ip_ntoa(&ip->ip_src));
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", ip_ntoa(&ip->ip_dst));
    printf("+---------------------------------------------------+\n");

    switch (protocol) {
        case IPPROTO_UDP:
            dump_udp(length, content);
            break;

        case IPPROTO_TCP:
            dump_tcp(length, content);
            break;

        case IPPROTO_ICMP:
            printf("Next is ICMP\n");
            break;

        default:
            printf("Next is %d\n", protocol);
            break;
    }//end switch
}//end dump_ip

char *tcp_ftoa(u_int8_t flag) {
    static int  f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    u_int32_t mask = 1 << 7;
    int i;

    for (i = 0; i < TCP_FLG_MAX; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = '\0';

    return str;
}//end tcp_ftoa

void dump_tcp(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);

    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("+---------------------------------------------------+\n");
    printf("| Acknowledgement Number:                 %10u|\n", ack);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", header_len, tcp_ftoa(flags), window);
    printf("+------+-------+----------+-------------------------+\n");
    printf("| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    printf("+-------------------------+-------------------------+\n");
}//end dump_tcp