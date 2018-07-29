#include <stdio.h>
#include <pcap.h>
#include <errno.h>

typedef struct ethernet_header {
	unsigned char dmac[6];
	unsigned char smac[6];
	unsigned char type[4];	
} EthHeader;

typedef struct ip_header {
	unsigned char length;
	unsigned char protocol;
	unsigned char saddr[4];
	unsigned char daddr[4];
} IPHeader;

typedef struct tcp_header {
	unsigned char srcport[2];
	unsigned char dstport[2];
} TCPHeader;


int Ethernet_Header_Parsing (const u_char * packet, EthHeader * ethheader){
	int i;

	printf("\n"); 

	for (i = 0; i < 6; i++)
		ethheader->dmac[i] = (unsigned char)packet[i];

	for (i = 0; i < 6; i++) 
		ethheader->smac[i] = (unsigned char)packet[i + 6];

	for (i = 0; i < 2; i++)
		ethheader->type[i] = (unsigned char) packet[i + 12];
	
	return 0;
};

int IP_Header_Parsing (const u_char * packet, IPHeader * IPheader) {
	int i = 0;

	IPheader->length = packet[0] & 0x0F;
	IPheader->protocol = packet[9];

	for (i = 0; i < 4; i++)
		IPheader->saddr[i] = (unsigned char) packet[i + 12];

	for (i = 0; i < 4; i++)
		IPheader->daddr[i] = (unsigned char) packet[i + 16];

	return 0;
};

int TCP_Header_Parsing(const u_char * packet, TCPHeader * TCPheader) {
	int i = 0;
	*((unsigned short *)TCPheader->srcport) = ntohs(*((unsigned short *)packet));
	*((unsigned short *)TCPheader->dstport) = ntohs(*((unsigned short *)&packet[2]));

	return 0;
};

int main (int argc, char * argv[]) {
	char * dev;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * pcd;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	const u_char * packet;
	struct pcap_pkthdr header;
	struct bpf_program fp;
	EthHeader ethheader;
	IPHeader IPheader;
	TCPHeader TCPheader;
	
	if (argc > 1) {
		dev = argv[1];		
	}
	else {
		printf("Find a device automatically...\n");
		dev = pcap_lookupdev(errbuf);
		
		if(dev == NULL) {
			fprintf(stderr, "Couldn't find device : %s\n", errbuf);
			return 2;
		}
	}
	
	printf("Device : %s\n", dev);	
	
	pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (pcd == NULL) {
		fprintf(stderr, "Cannot open device(%s) : %s\n", dev, errbuf);
		return 2;
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Cannot get netmask for device(%s) : %s\n", dev, errbuf);
	}
	
	if ((pcap_datalink(pcd)) != DLT_EN10MB) {
		fprintf(stderr, "Device %s does not provide Ethernet header", dev);
		return 2;
	}
	
	printf("Data-link Layer check completed...(type : Ethernet)\n");	


	while(1) {

		packet = pcap_next(pcd, &header);
		
		if (packet == NULL)
			continue;
		
		printf("\n/**** PACKET INFO ****/\n");
		printf("captured packet length(%d)\n", header.len);
		

		Ethernet_Header_Parsing (packet, &ethheader);
		printf("* Data Link Layer :\n");

		printf("dst MAC address : ");
		for (i = 0; i < 6; i++)
			printf("%02X ", ethheader.dmac[i]);
		printf("\n");
		
		printf("src MAC address : ");
		for (i = 0; i < 6; i++) 
			printf("%02X ", ethheader.smac[i]);
		printf("\n");
		
		printf("type : %02X %02X\n", ethheader.type[0], ethheader.type[1]);


		printf("\n* Network Layer : \n");

		if (ntohs(*((unsigned short *)ethheader.type)) != 0x0800) {
			printf("Packet is NOT IPv4\n");
			continue;
		}

		IP_Header_Parsing (packet + 14, &IPheader);

		printf("IP header lenth : %d bytes\n", IPheader.length << 2);
		printf("protocol : %d(0x%02X)\n", IPheader.protocol, IPheader.protocol);
		printf("src IP address : ");
		for (i = 0; i < 4; i++) {
			if (i != 3) printf("%d.", IPheader.saddr[i]);
			else 		printf("%d\n",  IPheader.saddr[i]);
		}

		printf("dst IP address : ");
		for (i = 0; i < 4; i++) {
			if (i != 3) printf("%d.", IPheader.daddr[i]);
			else 		printf("%d\n",  IPheader.daddr[i]);	
		}
		
		printf("\n* Transport Layer\n");

		if (IPheader.protocol != 0x06) {
			printf("This Packet is NOT TCP...\n");
			continue;
		}

		TCP_Header_Parsing(packet + 14 + (IPheader.length * 4), &TCPheader);

		printf("src port : %d\n", *((unsigned short *)TCPheader.srcport));
		printf("dst port : %d\n", *((unsigned short *)TCPheader.dstport));

		printf("\n* PACKET DATA : \n");
		for (i = 0; i < header.len; i++) {
			if (i == 0)				printf("%02X ",   packet[0]);
			else if ((i % 16) == 0)	printf("\n%02X ", packet[i]);
			else if ((i % 8) == 0)	printf(" %02X ",  packet[i]);
			else 					printf("%02X ",   packet[i]);
		}
		printf("\n");	
			
	}

	pcap_close(pcd);

	return 0;		
}
