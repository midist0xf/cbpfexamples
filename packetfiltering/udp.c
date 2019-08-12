#include <arpa/inet.h>
#include <string.h>
#include <linux/filter.h> //sock_filter sock_fprog
#include <stdio.h>
#include <stdlib.h>

#define BUFLEN 65507 
#define PORT 55555    
#define NPACK 10

struct sock_filter bpfcode[] = {  

   /*  
    * At each level the filter is applied to the payload of that specific level.
    * The level is defined by the type of socket we use. The more the packet
    * travels upward the less information is visible to the filter.
    * tcpdump use a packet socket which also see the data link information. 
    * Using an UDP socket we can't use the tcpdump -dd output as it is
    * because packets travel at an higher level in the network stack compared
    * to a packet socket.
    * In this example is used an UDP socket, therefore  we can access directly
    * to the UDP header and consequently to load the src port field the starting 
    * offset is 0. 
    */

   /* src port 1030 */
   { 0x28, 0, 0, 0x00000000 }, // load UPD header src port field
   { 0x15, 0, 1, 0x00000406 }, // check if src port field is 1030
   { 0x6, 0, 0, 0x00040000 },  // return the entire packet
   { 0x6, 0, 0, 0x00000000 },  // discard the packet
   
   /* compare the filter above with the following tcpdump output */
   /* tcpdump udp and src port 1030 -dd */ 
   /*
   { 0x28, 0, 0, 0x0000000c },  load ethernet type field                            |---
   { 0x15, 0, 4, 0x000086dd },  check if the ethernet type field is IP6             |
   { 0x30, 0, 0, 0x00000014 },  load IP6 header next header field                   |
   { 0x15, 0, 11, 0x00000011 }, check if next header field is UDP                   |
   { 0x28, 0, 0, 0x00000036 },  load UPD header src port field                      |
   { 0x15, 8, 9, 0x00000406 },  check if src port field is 1030                     |  these instructions are relative to
   { 0x15, 0, 8, 0x00000800 },  check if the ethernet type field is IP4             |  lower layers, so to information that
   { 0x30, 0, 0, 0x00000017 },  load IP4 header protocol field                      |  with UDP socket we can't see
   { 0x15, 0, 6, 0x00000011 },  check if protocol field is UDP                      |
   { 0x28, 0, 0, 0x00000014 },  loads flag and fragment offset field                |
   { 0x45, 4, 0, 0x00001fff },  check if fragment offset is 0 (first fragment)      |
   { 0xb1, 0, 0, 0x0000000e },  load internet header length in the index register   |---
   { 0x48, 0, 0, 0x0000000e },  load UPD header src port field                      |+++
   { 0x15, 0, 1, 0x00000406 },  check if src port field is 1030                     |
   { 0x6, 0, 0, 0x00040000 },   return the entire packet                            |  visible information
   { 0x6, 0, 0, 0x00000000 },   discard the packet                                  |+++
   */


   /* src port 1030 rewritten with macro */
   /*
   // check if UDP src port field is 1030 
   BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 0),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x406, 0, 1),
   // return the entire packet 
   BPF_STMT(BPF_RET+BPF_K, 0x40000),
   // discard the packet 
   BPF_STMT(BPF_RET+BPF_K, 0),
   */


   /* tcpdump udp and src port 1030 -dd rewritten with macro */
   /*
   // check if the ethernet type field is ip6 
   BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x86dd, 0, 4),
   // check if the next header field is UDP 
   BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 20),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x11, 0, 11),
   // check if the UPD header src port is 1030 
   BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 54),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x406, 8, 9),
   // check if the ethernet type field is ip4 
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 8),
   // check if the ip4 header protocol field is UDP 
   BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x11, 0, 6),
   // check if ip4 header fragment offset is 0 
   BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20), 
   BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 4, 0),
   // load ip4 header length in the index register 
   BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
   // check if UDP src port is 1030 
   BPF_STMT(BPF_LD+BPF_H+BPF_IND, 14),
   BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x406, 0, 1),
   // return the entire packet 
   BPF_STMT(BPF_RET+BPF_K, 0x40000),
   // discard the packet 
   BPF_STMT(BPF_RET+BPF_K, 0),
   */


};

int main(int argc, char *argv[]){

   struct sockaddr_in servaddr;     

   memset(&servaddr, 0, sizeof(servaddr));
   
   /* fill address information */
   servaddr.sin_family=AF_INET;
   servaddr.sin_addr.s_addr=INADDR_ANY;
   servaddr.sin_port=htons(PORT);
      
   /* create socket file descriptor for UDP protocol */
   int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if (fd < 0){
      printf("socket");
      return -1;
   }

   struct sock_fprog bpf = { sizeof(bpfcode)/sizeof(struct sock_filter), bpfcode};
  
   /* attach bpf program to the socket */
   int ret = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
   if (ret < 0){
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   /* bind the local address to the socket */
   int n;
   n = bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
   if (n < 0){
      printf("bind");
      return -1;
   }

   /* receive some packets */
   char buf[BUFLEN];
   int i;
   for(i=0; i<NPACK; i++){
      int res = recvfrom(fd, buf, sizeof(buf), 0, NULL, 0);
      printf("res=%d\n", res);
   }

   /* close the socket */
   close(fd);

   return 0;
}
