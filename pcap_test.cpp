#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

struct ip *iph;
struct tcphdr *tcph;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(struct ether_header *ep){
    printf("S-MAC:");
    printf("%02x:%02x:%02x:%02x:%02x:%02x", ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2], ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);
    printf("\n");

    printf("D-MAC:");
    printf("%02x:%02x:%02x:%02x:%02x:%02x", ep->ether_dhost[0], ep->ether_dhost[1], ep->ether_dhost[2], ep->ether_dhost[3], ep->ether_dhost[4], ep->ether_dhost[5]);
    printf("\n");
}

void print_ipheader(struct ip *iph){
	printf("**IP packet**\n");
        printf("Version     : %d\n", iph->ip_v);
        printf("Header Len  : %d\n", iph->ip_hl);
        printf("Ident       : %d\n", ntohs(iph->ip_id));
        printf("TTL         : %d\n", iph->ip_ttl);
        printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address : %s\n\n", inet_ntoa(iph->ip_dst));
}

void print_tcpheader(struct tcphdr *tcpd){
	printf("**TCP packet**\n");
        printf("Src Port : %d\n" , ntohs(tcph->source));
        printf("Dst Port : %d\n\n" , ntohs(tcph->dest));
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  int i;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  struct ether_header *ep;
  unsigned short ether_type;
      

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    i = 0;


    struct pcap_pkthdr* header;
    const u_char* packet;

    int res = pcap_next_ex(handle, &header, &packet);
    
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    int length = header -> len;
    ep = (struct ether_header *)packet;
    
    printf("==================ETH===================\n");
    print_mac(ep);
    printf("ether_header size : %ld\n\n", sizeof(struct ether_header));

    //ether_header size 만큼 빼줌.
    packet += sizeof(struct ether_header);
    length -= 14;
    ether_type = ntohs(ep->ether_type);

    //packet
    if (ether_type == ETHERTYPE_IP) //ETHERTYPE_IP : 0x0800
    {
        // ip header
       iph = (struct ip *)packet;
       print_ipheader(iph);

        //if tcp
        if (iph->ip_p == IPPROTO_TCP) // IPPROTO_TCP : 0x06
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            print_tcpheader(tcph);
	    
            //ip_header 와 tcp_header size만큼 빼줌.
            packet += (iph->ip_hl * 4)+(tcph -> doff * 4);
            length -= (iph->ip_hl * 4)+(tcph -> doff *4);

            //print data
            printf("DATA : ");
            while(length-- && i <= 10)
            {
                printf("%02x ", *(packet++));
                i++;
            }
    	    printf("\n==================END===================\n");
	 }

    }

  }

  pcap_close(handle);
  
  return 0;

}
