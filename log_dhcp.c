/*
	Code Reference  :
	How to code a Packet Sniffer in C with Linux Sockets – Part 2
	(Printing data dump, and headers)
	Author : Silver Moon
	link : shown in README

	DHCP packet structure (Documentation for the DHCP server)
	link : shown in README
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include<netinet/if_ether.h> //eth_p_all
#include<net/ethernet.h> //ethernet header
#include<netinet/ip.h> //ip header
#include<unistd.h>
#include<netinet/udp.h>  //udp header

#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)

/* defined for DHCP packet sniffer */
#define OPTION_SIZE 2048 
#define DISCOVER 1
#define REQUEST 3
#define OFFER 2
#define ACK 5

/* DHCP packet structure */
struct dhcp_packet{
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	unsigned int xid;
	unsigned short secs;
	unsigned short flags;
	unsigned char ciaddr[4];
	unsigned char yiaddr[4];
	unsigned char siaddr[4];
	unsigned char giaddr[4];
	unsigned char chaddr[16];
	unsigned char sname[64];
	char file[128];
	unsigned char options[OPTION_SIZE];
};

/* functions to use in DHCP packet sniffer */
void ProcessPacket(unsigned char* buffer, int size);
void print_udp_packet(unsigned char* message, int msg_length);
void print_ip_header(unsigned char* buffer, int size);
void print_ethernet_header(unsigned char* buffer, int size);


FILE* logfile;
struct sockaddr_in source,dest;

int main() {
	
	printf("starting program...\n");
	int saddr_size, data_size;
	struct sockaddr saddr;

	unsigned char* buffer = (unsigned char*)malloc(65536);

	/*  socket raw, eth_p_all to capture every incoming/outgoing packets */
	int socket_raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	/* log file : logDHCP.txt */
	logfile = fopen("./logDHCP.txt", "w+b");
	if (logfile == NULL)
		printf("Unable to create logDHCP.txt file");

	if (socket_raw < 0) {
		perror("socket make error");
		return 1;
	}

	while (1) {
		saddr_size = sizeof saddr;
		/* socket receive */
		data_size = recvfrom(socket_raw, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_size);
		
		
		if (data_size < 0) {
			printf("receive from not done\n");
			return 1;
		}
		/* ProcessPacket -> check if DHCP. if DHCP : process */
		ProcessPacket(buffer,data_size);
	}
	close(socket_raw);
	printf("finish\n");
	return 0;
}

/* print data dump */
void PrintData (unsigned char* data , int Size)
{
	/* data dump, 한 줄에 16바이트씩 - hex, char 로 출력 */
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile, "%c",(unsigned char)data[j]);

				else fprintf(logfile, ".");
			}
			fprintf(logfile, "\n");
		}

		if(i%16==0) fprintf(logfile, "   ");
			fprintf(logfile, " %02X",(unsigned int)data[i]);

		if( i==Size-1)  
		{
			for(j=0;j<15-i%16;j++)
			{
			  fprintf(logfile, "   "); 
			}

			fprintf(logfile, "         ");

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

/* analyze received socket, if DHCP: process */
void ProcessPacket(unsigned char* buffer, int size)
{
	/* ipheader: used to get ip header length*/
	struct iphdr* iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));
	unsigned short iphrlen=4*iph->ihl;
	/* udp header: udp header port number --> identify DHCP */
	struct udphdr* udp=(struct udphdr*)(buffer+sizeof(struct ethhdr)+iphrlen);
	const unsigned char* msg;
	int msgsize;

	/* DHCP: port 67, 68 */
	if((ntohs(udp->source)==67&&ntohs(udp->dest)==68)||(ntohs(udp->source)==68&&ntohs(udp->dest)==67)){
		/* udp header, ip header, ethernet header print */
		print_udp_packet(buffer,size);
		/* DHCP packet: after ethernet header & ip header */
		struct dhcp_packet* dhcp=(struct dhcp_packet*)(buffer+sizeof(struct ethhdr)+iphrlen+8);
		//printf("check magic position: %.2X-%.2X-%.2X-%.2X\n\n",dhcp->options[0],dhcp->options[1],dhcp->options[2],dhcp->options[3]);
		fprintf(logfile, "\n\n==DHCP Packet===\n\n");
		printf("get DHCP packet!\n");

		/* opcode: message type, 1-request, 2-reply */
		fprintf(logfile, "Message type: %d ",dhcp->op);
		if(dhcp->op==0x01)
			fprintf(logfile, "Request\n");
		else
			fprintf(logfile, "Reply\n");
		/* hardware type: 1-ethernet */
		fprintf(logfile,"Hardware type: %d ",dhcp->htype);
		if(dhcp->htype==0x01)
			fprintf(logfile, "Ethernet\n");
		else
			fprintf(logfile, "\n");
		/* hw add len: 6-mac */
		fprintf(logfile, "Hardware address length: %d\n",dhcp->hlen);
		/* hops */
		fprintf(logfile, "Hops: %d\n",dhcp->hops);
		/* transaction id */
		fprintf(logfile, "Transaction ID: 0x%08x\n",ntohl(dhcp->xid));
		/* number of seconds */
		fprintf(logfile, "Seconds elapsed: %d\n",ntohs(dhcp->secs));
		/* flag */
		fprintf(logfile, "Bootp flags: 0x%04x\n",dhcp->flags);
		/* client ip address */
		fprintf(logfile, "Client IP Address: %d.%d.%d.%d\n",dhcp->ciaddr[0],dhcp->ciaddr[1],dhcp->ciaddr[2],dhcp->ciaddr[3]);
		/* your ip address */
		fprintf(logfile, "Your (Client) IP Address: %d.%d.%d.%d\n",dhcp->yiaddr[0],dhcp->yiaddr[1],dhcp->yiaddr[2],dhcp->yiaddr[3]);
		/* server ip address */
		fprintf(logfile, "Next Server IP Address: %d.%d.%d.%d\n",dhcp->siaddr[0],dhcp->siaddr[1],dhcp->siaddr[2],dhcp->siaddr[3]);
		/* relay gateway ip address */
		fprintf(logfile, "Relay Agent IP Address: %d.%d.%d.%d\n",dhcp->giaddr[0],dhcp->giaddr[1],dhcp->giaddr[2],dhcp->giaddr[3]);
		
		/* client mac address-> 16byte, bytes left: padding (0) */
		int padding=0;
		/* client mac address */
		fprintf(logfile, "Client MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",dhcp->chaddr[0],dhcp->chaddr[1],dhcp->chaddr[2],dhcp->chaddr[3],dhcp->chaddr[4],dhcp->chaddr[5]);
		/* if next 6bytes are all 0? -> padding */
		if(dhcp->chaddr[6]==0x00&dhcp->chaddr[7]==0x00&&dhcp->chaddr[8]==0x00&&dhcp->chaddr[9]==0x00&&dhcp->chaddr[10]==0x00&&dhcp->chaddr[11]==0x00)
			padding=6;
		else{
			/* if not ? -> mac addr */
			fprintf(logfile, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",dhcp->chaddr[6],dhcp->chaddr[7],dhcp->chaddr[8],dhcp->chaddr[9],dhcp->chaddr[10],dhcp->chaddr[11]);
			padding=12;
		}
		/* print left bytes as padding */
		fprintf(logfile, "Client hardware address padding: ");
		for(int i=padding;i<16;i++)
			fprintf(logfile, "%.2X",dhcp->chaddr[i]);
		/* server host name */
		fprintf(logfile, "\nServer host name: ");
		int none=0;
		/* check if hostname 64bytes are all zero */
		for(int i=0;i<64;i++){
			if(dhcp->sname[i]!=0){
				none=1;
				break;
			}
		}
		/* if all 0? --> host name not given */
		if(none==0)
			fprintf(logfile, "not given\n");
		/* if not, print value */
		else
			fprintf(logfile, "%s\n",dhcp->sname);

		/* boot file name */
		fprintf(logfile, "Boot file name: ");
		int filename=0;
		/* file name 128bytes all zero --> not given */
		for(int i=0;i<64;i++)
			if(dhcp->file[i]!=0){
				filename=1;
				break;
			}
		if(filename==0)
			fprintf(logfile, "not given\n");
		else
			fprintf(logfile, "%s\n",dhcp->file);

		/* options field first 4bytes: Magic Cookie */
		if(dhcp->options[0]==0x63&&dhcp->options[1]==0x82&&dhcp->options[2]==0x53&&dhcp->options[3]==0x63)
			fprintf(logfile, "Magic coookie: DHCP\n");
		
		int point=4; 
		int length=0;
		int opt=0;
		/* field check until END */
		while(dhcp->options[point]!=0xff){
			/* option type 1byte, length 1 byte */
			fprintf(logfile, "Option: %d,  Length: %d\n",dhcp->options[point],dhcp->options[point+1]);
			opt=dhcp->options[point];
			length=dhcp->options[point+1];
			point+=2; 
			if(opt==0x35){  //type: message type
				fprintf(logfile, "Message type: %d ",dhcp->options[point]);
				int type=dhcp->options[point];
				/* type: discover, offer, request, ack */
				if(type==DISCOVER)
					fprintf(logfile, "Discover\n");
				else if(type==OFFER)
					fprintf(logfile, "Offer\n");
				else if(type==REQUEST)
					fprintf(logfile, "Request\n");
				else if(type==ACK)
					fprintf(logfile, "Ack\n");
			}//end of opt==0x35

			/* type: subnet mask */
			if(opt==0x01){
				fprintf(logfile, "Subnet Mask: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}

			/* type: router  */
			if(opt==0x03){
				fprintf(logfile, "Router: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);

			}

			/* type: domain name server */
			if(opt==0x06){
				fprintf(logfile, "Domain Name Server: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}

			/* type: domain name */
			if(opt==0x0f){
				fprintf(logfile, "Domain Name: ");
				for(int i=0;i<length;i++)
					fprintf(logfile, "%c",dhcp->options[point+i]);
				fprintf(logfile,"\n");
			}

			/* type: host name */
			if(opt==0x0c){
				fprintf(logfile, "Host Name: ");
				for(int i=0;i<length;i++)
					fprintf(logfile, "%c",dhcp->options[point+i]);
				fprintf(logfile, "\n");
			}

			/* type: broadcast address */
			if(opt==0x1c){
				fprintf(logfile, "Broadcast Address: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}

			/* type: DHCP server identifier */
			if(opt==0x36){
				fprintf(logfile, "DHCP Server Identifier: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}
			/* ip address lease time */
			if(opt==0x33){
				int time=dhcp->options[point]<<24|dhcp->options[point+1]<<16|dhcp->options[point+2]<<8|dhcp->options[point+3];
				fprintf(logfile, "IP Address Lease Time: (%ds) %dminutes\n",time,time/60);
			}
			/* netbios */
			if(opt==0x2c){
				fprintf(logfile, "NetBIOS over TCP/IP Name Server: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}
			/* requested ip */
			if(opt==0x32){
				fprintf(logfile, "Requested IP Address: %d.%d.%d.%d\n",dhcp->options[point],dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3]);
			}
			/* parameter list */
			if(opt==0x37){
				fprintf(logfile, "Parameter Request List\n");
				for(int i=0;i<length;i++){
					/* print only type number  */
					fprintf(logfile, "Parameter Request List Item: (%d)\n",dhcp->options[point+i]);
				}
			}
			/* client identifier */
			if(opt==0x3d){
				fprintf(logfile, "Client Identifier\n");
				fprintf(logfile, "Hardware type: %d ",dhcp->options[point]);
				/* 1 : ethernet */
				if(dhcp->options[point]==0x01)
					fprintf(logfile, "Ethernet\n");
				else
					fprintf(logfile, "\n");
				/* client mac addr */
				fprintf(logfile, "Client MAC Address: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",dhcp->options[point+1],dhcp->options[point+2],dhcp->options[point+3],dhcp->options[point+4],dhcp->options[point+5],dhcp->options[point+6]);
			}

			/* vendor class identifier */
			if(opt==0x3c){
				fprintf(logfile, "Vendor Class Identifier: ");
				for(int i=0;i<length;i++)
					fprintf(logfile, "%c",dhcp->options[point+i]);
				fprintf(logfile,"\n");
			}

			/* move point back as much as length (=size of data) */
			point+=length;
			
		}//end of while
		/* options last field: 255, END */
		if(dhcp->options[point]==0xff){
			fprintf(logfile, "Option: %d\n",dhcp->options[point]);
			fprintf(logfile, "End\n");
		}
		fflush(logfile);
	}//end of if dhcp packet (udp port)


}
     /* print ethernet header */
void print_ethernet_header(unsigned char* Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile, "   Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile, "   Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile, "   Protocol            : %u, 0x%02X%02X \n",(unsigned short)eth->h_proto,Buffer[12],Buffer[13]);
}

/* print ip header */
void print_ip_header(unsigned char* Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile, "   IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile, "   Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile, "   IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile, "   Identification    : %d\n",ntohs(iph->id));
	fprintf(logfile, "   TTL (Time To Live)     : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile, "   Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile, "   Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile, "   Source IP        : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile, "   Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

/* print udp header */
void print_udp_packet(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile,"\n\n***********************DHCP  -  UDP Packet*************************\n");
	
	print_ip_header(Buffer,Size);			
	
	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "   Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile, "   Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile, "   UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile, "   UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile, "\n");
	fprintf(logfile, "\n");
	fprintf(logfile, "                        DATA Dump                         ");
	fprintf(logfile, "\n");

	fprintf(logfile, "Data Dump in hex, char \n");
	PrintData(Buffer, Size );

	fprintf(logfile, "\n###########################################################\n\n");

	
}
