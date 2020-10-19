/*  Projekt 2 IPK 2019/2020
    Packet sniffer
    Adam Ševčík
    xsevci64 
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <stdbool.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   
#include <netinet/udp.h>  
#include <netinet/tcp.h>   
#include <netinet/ip.h>   

void udp_packet_print(const u_char * , int, char*);
void tcp_packet_print(const u_char * , int, char*);
void print_ip_header(const u_char * , int, int, int,char*);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void data_print (const u_char * , int);

struct pcap_pkthdr hdr;
struct sockaddr_in source,dest;
struct bpf_program fp;
const u_char *packet;
char filter_p[] = "port ";
char filter_u[] = "udp ";
char filter_t[] = "tcp ";
bool par_i = false;
bool par_p = false;
bool par_tcp = false;
bool par_udp = false;
int par_n = 1;
char* rozhranie;
char* port;
bpf_u_int32 mask;
bpf_u_int32 net;


int main(int argc, char* argv[] )
{
    char* total = malloc(15 * sizeof(char));
    char* filter = malloc(22 * sizeof(char));
//spracovanie argumentov
    for(int i = 1; i < argc; i++){
//argument rozhrania
        if(!strcmp(argv[i],"-i")){
            
            rozhranie = argv[i+1];
            
            par_i = true;
        }
//argument portu

        else if(!strcmp(argv[i], "-p")){
            if(argv[i+1]== NULL){
            printf("Chybajuca hodnota parametru -p !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
            exit(1);
            }
            port = argv[i+1];
            char* tmp;
            int int_p = strtol(argv[i+1], &tmp ,10);
            if(strcmp(tmp,"")){
                printf("Parameter -p musi byt integer !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
                exit(1);
            }
            if(int_p <= 0 || int_p >= 65535){
                printf("Nesprávny port v parametri -p ! Port musi byt integer medzi 1 a 65535 !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
                exit(1);
            }
            par_p = true;
//nakopirovanie portu do filteru
            memcpy(total,     filter_p, 5 * sizeof(char)); 
            memcpy(total + 5, port, 6 * sizeof(char));
        }
//argument protocolu tcp
        else if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--tcp")){
            par_tcp = true;
            
            
        }
//argument protocolu udp
        else if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udp")){
            par_udp = true;
            
        }
//argument poctu sniffovanych packetov
        else if(!strcmp(argv[i],"-n")){
            if(argv[i+1]== NULL){
            printf("Chybajuca hodnota parametru -n !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
            exit(1);
            }
            char* tmp;
            par_n = strtol(argv[i+1], &tmp ,10);
            if(strcmp(tmp,"")){
                printf("Parameter -n musi byt integer !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
                exit(1);
            }
            if(par_n < 0){
                printf("Parameter -n nesmie byt mensi ako 0 !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
                exit(1);
            }
            else if(par_n == 0){
                printf("Parameter -n musi byt integer vacsi ako 0 !!! Spustenie: ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
                exit(1);
            }
            
        }
    }
//vytvorenie filtru pre pripad oboch protocolov
    if((par_udp == true && par_tcp == true) || (par_udp == false && par_tcp == false) ){

        memcpy(filter, filter_u,4*sizeof(char));
        memcpy(filter + 4, "|| ",3*sizeof(char));
        memcpy(filter + 7, filter_t,4*sizeof(char));
        memcpy(filter + 11, total, 10 * sizeof(char));
        
    }
//vytvorenie filtru pre udp
    else if(par_udp == true && par_tcp == false){

        memcpy(filter,     filter_u, 4 * sizeof(char)); 
        memcpy(filter + 4, total, 15 * sizeof(char));
    }
//vytvorenie filtru pre tcp
    else if(par_tcp == true && par_udp == false){

        memcpy(filter,     filter_t, 4 * sizeof(char)); 
        memcpy(filter + 4, total, 15 * sizeof(char));
    }
    

    pcap_if_t *alldevsp , *device;
    pcap_t *handle; 
 
    char errbuf[100];
     
//vypisanie dostupnych rozhrani
    if(rozhranie == NULL){

    if(pcap_findalldevs( &alldevsp , errbuf))
    {
        printf("Chyba pri hladani rozhrania! ");
        exit(1);
    }
    printf("Pristupne rozhrania :\n");
    for(device = alldevsp ; device != NULL ; device = device->next){
        printf("%s - %s\n" , device->name , device->description);  
    }
    exit(0);
    }
     

     if(pcap_lookupnet(rozhranie, &net, &mask, errbuf) == -1){
         net =0;
         mask =0;
     }
//otvorenie konkretneho rozhrania    
    handle = pcap_open_live(rozhranie , 65536 , 1 , 0 , errbuf);
    
    if (handle == NULL){ 
    
        fprintf(stderr, "Nemozno otvorit rozhranie %s!\n" , rozhranie);
        exit(1);
    }
   
    if(port != 0 || par_tcp == true || par_udp == true){

  if(pcap_compile(handle,&fp, filter, 0, net) == -1){

      printf("Chyba pri kompilacii\n!");
      return(1);
  }

  if(pcap_setfilter(handle, &fp) == -1){

      printf("Chyba pri vytvarani filtru\n!");
      return(1);
  }
  }
//spustenie sniffovacieho loopu podla argumentu n
    pcap_loop(handle , par_n , process_packet , NULL);
    free(total);
    free(filter);
    return 0;   

}
//funkcia na zacatie sniffovania konkretheno packetu
 void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
     int size = header->len;

//ziskanie casu prijatia packetu
    char time[32];
    char ms[7];
    struct tm lt = *localtime(&header->ts.tv_sec);
    strftime(time,20,"%H:%M:%S." , &lt);
    sprintf(ms,"%ld",header->ts.tv_usec);
    strcat(time,ms);
     
//rozhodnutie o tom aky protocol ma packet
     if(par_tcp == true && par_udp == false){

        tcp_packet_print(buffer, size, time);
    } 
    if(par_udp == true && par_tcp ==false){

        udp_packet_print(buffer , size, time);
    }
    if((par_tcp == false && par_udp == false )|| (par_tcp == true && par_udp == true)){
        
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

        if(iph->protocol == 6){
            
           tcp_packet_print(buffer , size, time); 
        }
        else if(iph->protocol == 17){
      
            udp_packet_print(buffer , size, time);
        }
    }
 }



//funkcia na spracovanie protocolu UDP
 void udp_packet_print(const u_char * buffer, int size, char* time){
     unsigned short iphdrlen;
     
  

    struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
       
    struct tcphdr *udph=(struct tcphdr*)( buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

//ziskanie source a destination portu
    int source_port = ntohs(udph->source);
    int dest_port = ntohs(udph->dest);

//vypisanie headeru s casom ip a portom
    print_ip_header(buffer,size,source_port,dest_port,time);

//vypisanie headeru
    data_print(buffer,header_size);

//vypisanie dat 
    data_print(buffer - header_size, size + header_size);
 }





//funkcia na spracovanie protocolu TCP
 void tcp_packet_print(const u_char * buffer, int size, char* time){
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)( buffer + iphdrlen + sizeof(struct ethhdr));

   int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

//ziskanie source a destionation portu
    int source_port = ntohs(tcph->source);
    int dest_port = ntohs(tcph->dest);

//vypisanie headeru s casom ip a portom   
    print_ip_header(buffer,size,source_port,dest_port,time);

//vypisanie headeru
    data_print(buffer,header_size);

//vypisanie dat 
    data_print(buffer - header_size, size + header_size);

 }
//funkcia na vypisanie prveho riadku packetu s casom prijatia a source a destination ip a portu
 void print_ip_header(const u_char * buffer, int size, int source_port, int dest_port,char* time){

     unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

//ziskanie source ip  
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

//sikanie destination ip
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char* ip_src =(char*)malloc(sizeof(char)*256);
    char* ip_dest =(char*)malloc(sizeof(char)*256);
    char* buf6 = (char*)malloc(sizeof(INET6_ADDRSTRLEN*sizeof(char)));

    char* dest_ip;
    char* source_ip;

//zmena ip na hostname pre ipv4
    if((unsigned int)iph->version == 4){
    strcpy(ip_src,inet_ntoa(source.sin_addr));
    strcpy(ip_dest,inet_ntoa(dest.sin_addr));
    
    }
//zmena ip na hostname pre ipv6
    else if((unsigned int)iph->version == 6){ 
    strcpy(ip_src,inet_ntop(AF_INET6, &source.sin_addr, buf6, sizeof(buf6)));
    strcpy(ip_dest,inet_ntop(AF_INET6, &dest.sin_addr, buf6, sizeof(buf6)));

    
    
    }

//vypisanie prveho riadku
    printf("%s %s : %d > %s : %d\n \n",time,ip_src,source_port,ip_dest,dest_port);
    free(ip_src);
    free(ip_dest);
    free(buf6);
 }

//funkcia na vypisanie dat packetu
void data_print (const u_char * data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {

//ak sa dokonci vypisanie jedneho riadku     
        if( i!=0 && i%16==0) 
        {
            printf("  ");
            for(j=i-16 ; j<i ; j++)
            {

//ak je to stlacitelny znak
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); 
                    
//ak je to nieco ine vypis bodku 
                else printf("."); 
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("%#06x: ",i);
            printf(" %02X",(unsigned int)data[i]);
        if( i==Size-1)
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); 
            }
            
            printf("  ");
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  printf("%c",(unsigned char)data[j]);
//ak je to stlacitelny znak
                }
                else
                {
//ak je to nieco ine vypis bodku 
                  printf(".");
                }
            }
             
            printf("\n");
        }
        
    }
    printf("\n");

    
}
