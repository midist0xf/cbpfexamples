#include <sys/types.h>       
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h> //sock_filter sock_fprog
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <string.h>
#include <stdio.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdlib.h>

#define DEFAULT_IF   "eth0"
/* REFERENCES: 
https://www.kernel.org/doc/Documentation/networking/filter.txt */

/* define cbpf program */
struct sock_filter bpfcode[] = {  

   /* icmp echo-reply */
   
   /* check if ethernet field type is ip4 */              
   BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),                    
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 8),          
   /* check if ip protcol field is icmp             */    
   BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),                    
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x1, 0, 6),            
   /* check if fragment offset is 0 */                    
   BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),                    
   BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 4, 0),        
   /* load ip header length in the index register */      
   BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),                   
   /* check if icmp type is echoreply */                  
   BPF_STMT(BPF_LD+BPF_B+BPF_IND, 14),                    
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0, 0, 1),            
   /* return the entire packet */                         
   BPF_STMT(BPF_RET+BPF_K, 0x40000),                      
   /* discard the packet */                               
   BPF_STMT(BPF_RET+BPF_K, 0),                            

};

/*
  +----+----+----+----+----+----+----+----+----+----+----+----+----+----+ 
  |        Source MAC           |      Destination MAC        |  Ether  | 
  |                             |                             |  type   | 
  +----+----+----+----+----+----+----+----+----+----+----+----+----+----+ 
  */
void print_ethernet_header(unsigned char* buffer){

   struct ethhdr *eth = (struct ethhdr *)buffer;

   printf("Ethernet Header\n");
   printf("    +Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
   printf("    +Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
   printf("    +Protocol            : 0x%x \n", ntohs(eth->h_proto));
}

/*
  0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
*/
void print_ip_header(unsigned char* buffer){

   struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   struct sockaddr_in src, dst;

   memset(&src, 0, sizeof(src));
   memset(&dst, 0, sizeof(dst));

   src.sin_addr.s_addr = iph->saddr;
   dst.sin_addr.s_addr = iph->daddr;

   printf("IP Header\n");
   printf("    +Version           : %u\n", (unsigned int)iph->version);
   printf("    +IHL               : %u\n", (iph->ihl)*4);
   printf("    +TOS               : %u\n", iph->tos);
   printf("    +IP Total Length   : %u B\n", ntohs(iph->tot_len));
   printf("    +Identification    : %u\n", ntohs(iph->id));
   printf("    +Fragment offset   : %u\n", ntohs(iph->frag_off));
   printf("    +TTL               : %u\n", iph->ttl);
   printf("    +Protocol          : %u\n", iph->protocol);
   printf("    +Checksum          : %u\n", ntohs(iph->check));
   printf("    +Source IP         : %s\n" , inet_ntoa(src.sin_addr) );
   printf("    +Destination IP    : %s\n" , inet_ntoa(dst.sin_addr) );
}

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
*/
void print_tcp_header(char* buffer){
   
   struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   unsigned short iphdrlen = 4*(iph->ihl);
   struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
    
   printf("TCP Header\n");
   printf("    +Source Port        : %u\n", ntohs(tcph->source));
   printf("    +Destination Port   : %u\n", ntohs(tcph->dest));
   printf("    +Sequence Number    : %u\n", ntohl(tcph->seq));
   printf("    +Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
   printf("    +Data Offset        : %u\n", tcph->doff);
   printf("    +URG                : %u\n", tcph->urg); 
   printf("    +ACK                : %u\n", tcph->ack);
   printf("    +PSH                : %u\n", tcph->psh);
   printf("    +RST                : %u\n", tcph->rst);
   printf("    +SYN                : %u\n", tcph->syn);
   printf("    +FIN                : %u\n", tcph->fin);
   printf("    +Window Size        : %u\n", ntohs(tcph->window));
   printf("    +Checksum           : %u\n", ntohs(tcph->check)); 
}
/*
  0      7 8     15 16    23 24    31  
 +--------+--------+--------+--------+ 
 |     Source      |   Destination   | 
 |      Port       |      Port       | 
 +--------+--------+--------+--------+ 
 |                 |                 | 
 |     Length      |    Checksum     | 
 +--------+--------+--------+--------+ 
 |                                     
 |          data octets ...            
 +---------------- ...                 
*/
void print_udp_header(char* buffer){

   struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   unsigned short iphdrlen = 4*(iph->ihl);
   struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

   printf("UDP Header\n");
   printf("    +Source port: %u\n", ntohs(udph->source));
   printf("    +Destination port: %u\n", ntohs(udph->dest));
   printf("    +Length: %u\n", ntohs(udph->len));
   printf("    +Checksum: %u\n", ntohs(udph->check));
}

/*
 0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
*/
void print_icmp_header(char* buffer){

   struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   unsigned short iphdrlen = 4*(iph->ihl);
   struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);

   printf("ICMP Header\n");
   printf("    +Type            : %u\n", icmph->type);
   printf("    +Code            : %u\n", icmph->code);
   printf("    +Checksum        : %u\n", ntohs(icmph->checksum));
   printf("    +Identifier      : %u\n", ntohs(icmph->un.echo.id));
   printf("    +Sequence Number : %u\n", ntohs(icmph->un.echo.sequence));
}

int main(int argc, char *argv[]){
   
   char ifname[IFNAMSIZ];
   int ret;
   char buffer[65536]; // loopback interface MTU size is 65536 
   memset(buffer, 0, sizeof(buffer));

   // get interface name 
   if (argc > 1){
      strcpy(ifname, argv[1]);
   } else {
      strcpy(ifname, DEFAULT_IF);
   }

   // create a raw socket which receives all kind of protocols
   int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
   if( sfd < 0){
      perror("socket");
      exit(EXIT_FAILURE);
   }

   struct sock_fprog bpf = { sizeof(bpfcode)/sizeof(struct sock_filter), bpfcode};
   
   // attach bpf filter to the raw socket 
   ret = setsockopt(sfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
   if (ret < 0){
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   // to bind a packet socket to a specific interface 
   // is necessary to set sll_family, sll_protocol and  sll_ifindex
   // of a struct sockaddr_ll
   struct sockaddr_ll addr;
   memset(&addr, 0, sizeof(addr));
   addr.sll_family = AF_PACKET;
   addr.sll_protocol = htons(ETH_P_ALL);
   addr.sll_ifindex = if_nametoindex(ifname);

   // an address is assigned to the socket 
   if(bind(sfd, (struct sockaddr *) &addr, sizeof(addr) ) == -1){
      perror("bind");
      exit(EXIT_FAILURE);
   }     
  
   int saddr_len = sizeof(struct sockaddr_ll);

   // receive some packets 
   int i;
   for(i = 0; i < 200; i++){
      int r;
      r = recvfrom(sfd, buffer, sizeof(buffer), 0,  (struct sockaddr *)&addr, (socklen_t*)&saddr_len);
      if(r < 0){
	  perror("recvfrom");
          exit(EXIT_FAILURE);
      }
	   
      print_ethernet_header(buffer);
      print_ip_header(buffer);
      print_icmp_header(buffer);
      //print_tcp_header(buffer);
      //print_udp_header(buffer);
   }

   close(sfd);
   
}
