/*	
	Code Reference  :
	How to code a Packet Sniffer in C with Linux Sockets – Part 2
	(Printing data dump, and headers)
	Author : Silver Moon
	link : shown in README
*/

#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>	
#include<stdlib.h>	
#include<string.h>	

#include<netinet/if_ether.h>	//use ETH_P_ALL
#include<net/ethernet.h>	//ethernet header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

struct arp_ha {
	unsigned char ha[6];
};
struct arp_pa {
	unsigned char pa[4];
};
//arp header: total 28byte, used to analyze arp pacekt 
struct arp_packet {
	uint16_t ar_hrd; //hardware type 2byte
	uint16_t ar_pro;//protocol type 2byte
	uint8_t ar_hln;//hw add len
	uint8_t ar_pln;//ip add len
	uint16_t ar_op;//opcode
	struct arp_ha ar_sha;//src hw add
	struct arp_pa ar_spa;//src protocol add
	struct arp_ha ar_tha;//target hw add
	struct arp_pa ar_tpa;//target protocol add
};

/* file to log packet */
FILE *logfile;

/* functions used */
void ProcessPacket(unsigned char* , int); 
void PrintData (unsigned char* , int);
void print_ethernet_header(unsigned char*,int);

int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
		
	/* buffer to save recvfrom */
	unsigned char *buffer = (unsigned char *) malloc(65536); 

	logfile = fopen("./logARP.txt", "w+b");
	if (logfile == NULL)
		printf("Unable to create logARP.txt file");
	
	/* raw socket, eth_p_all socket to capture every imcoming/outgoing packets */
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	
	if(sock_raw < 0)
	{
		/*print error if packet err*/
		perror("Socket Error");
		return 1;
	}

	printf("sniffing start!\n");
	/*recv all packets*/
	while(1)
	{
		saddr_size = sizeof saddr;
		/*recvfrom packets! */
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		/*ethernet header의 protocol -> check if arp */
		struct ethhdr* eth=(struct ethhdr*)buffer;
		/*ethernet protocol= 0x0806, ARP packet! --> process */
		if(ntohs(eth->h_proto)==0x0806)
			ProcessPacket(buffer , data_size);
	}
	close(sock_raw);
	printf("Finished");
	return 0;
}

/* print data dump */
void PrintData (unsigned char* data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		/*16바이트 씩 끊어서 출력, hex로 출력한 후 char 형으로 내용 출력*/
		if( i!=0 && i%16==0)  
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if char or num, print

				else fprintf(logfile,"."); //if not, print as .
			}
			fprintf(logfile,"\n");
		}

		if(i%16==0) printf("   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);

		if( i==Size-1)  
		{
			for(j=0;j<15-i%16;j++)
			{
			  fprintf(logfile,"   "); 
			}

			fprintf(logfile,"         ");

			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
				{
				  fprintf(logfile, "%c",(unsigned char)data[j]);
				}
				else
				{
				  fprintf(logfile, ".");
				}
			}

			fprintf(logfile, "\n" );
		}
	}
}

/* printing arp packet */
void ProcessPacket(unsigned char* buffer, int size)
{
		fprintf(logfile, "\n\n\n=============================ARP Packet=========================\n\n");
		/* print ethernet header */
		print_ethernet_header(buffer,size);
		printf("check arp packet!\n");
		
		/*ARP structure, after ethernet header (14byte) */
		struct arp_packet* arp=(struct arp_packet*)(buffer+sizeof(struct ethhdr));
		/* hw type, if 0x0001 ethernet */
		if(htons(arp->ar_hrd)==0x0001)
			fprintf(logfile, "   Hardware type: Ethernet (%d)\n",htons(arp->ar_hrd));
		/*protocol type, ipv4*/
		if(htons(arp->ar_pro)==0x0800)
			fprintf(logfile, "   Protocol type: IPv4\n");
		/*hardware add len, ip add len*/
		fprintf(logfile, "   Hardware size: %d\n",arp->ar_hln);
		fprintf(logfile, "   Protocol size: %d\n",arp->ar_pln);
		/*opcode if 1=request, if 2=response*/
		if(htons(arp->ar_op)==0x0001)
			fprintf(logfile, "   Opcode: request (%d)\n",htons(arp->ar_op));
		if(htons(arp->ar_op)==0x0002)
			fprintf(logfile, "   Opcode: reply (%d)\n",htons(arp->ar_op));
		/*MAC, IP */
		fprintf(logfile, "   Sender MAC address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",arp->ar_sha.ha[0],arp->ar_sha.ha[1],arp->ar_sha.ha[2],arp->ar_sha.ha[3],arp->ar_sha.ha[4],arp->ar_sha.ha[5]);
		fprintf(logfile, "   Sender IP address: %d.%d.%d.%d\n",arp->ar_spa.pa[0],arp->ar_spa.pa[1],arp->ar_spa.pa[2],arp->ar_spa.pa[3]);
		fprintf(logfile, "   Target MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",arp->ar_tha.ha[0],arp->ar_tha.ha[1],arp->ar_tha.ha[2],arp->ar_tha.ha[3],arp->ar_tha.ha[4],arp->ar_tha.ha[5]);
		fprintf(logfile, "   Target IP Address: %d.%d.%d.%d\n",arp->ar_tpa.pa[0],arp->ar_tpa.pa[1],arp->ar_tpa.pa[2],arp->ar_tpa.pa[3]);

		/* if bytes left, print as padding */
		const unsigned char* padding=(const unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct arp_packet));
		int padSize=size-sizeof(struct ethhdr)-sizeof(struct arp_packet);
		if(padSize>0){
		fprintf(logfile, "   Padding: ");
		for(int i=0;i<padSize;i++){
			fprintf(logfile, "%02X",padding[i]);
		}
		}

		fflush(logfile);
			
}


/* print ethernet header */
void print_ethernet_header(unsigned char* Buffer, int Size)
{
	/*14byte ethernet header structure */
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, "   Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile, "   Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile, "   Protocol            : %u, 0x%02X%02X \n",(unsigned short)eth->h_proto,Buffer[12],Buffer[13]);

	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA Dump                         ");
	fprintf(logfile, "\n");


	fprintf(logfile, "Data Dump in Hex, char   \n");
	PrintData(Buffer, Size);

	fprintf(logfile, "\n\n\n");

}


