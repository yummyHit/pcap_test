/*
This code is made by UkjinJang using Microsoft Visual C++ 2010 Express.
You must have winpcap and add to library, include directory at your VC/bin directory.
+ Additional, install libnet and include it.
+ Additional, include <libnet-macros.h> in libnet-headers.h file.
Must be add linker: ws2_32.lib; wpcap.lib; Packet.lib

1. Go to "Project Properties..."
2. VC++ Directory -> Edit to "Include Directory" -> add your pcap header and libnet header such as "C:\Wpdpack\Include", "C:\libnet\include\win32"
3. VC++ Directory -> Edit to "Library Directory" -> add your pcap library such as "C:\Wpdpack\Lib"
4. C/C++ -> Precompiler -> Edit to "Precompiler definition" -> add "HAVE_REMOTE" and "WPCAP"

Done !

*/
#define HAVE_REMOTE
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>
#include <libnet.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

void mac_print(int init, struct libnet_ethernet_hdr *eth) {
	int i = 0;
	if(init == 0) {
		while(i < ETHER_ADDR_LEN) {
			printf("%02x:", eth->ether_shost[i]);	// print Source Mac Address
			if((i+1) == (ETHER_ADDR_LEN-1))		// If next i value is last index, print last address value and quit loop.
				printf("%02x", eth->ether_shost[++i]);
			i++;
		}
		printf("\n");
	}
	else {
		i = 0;
		while(i < ETHER_ADDR_LEN) {
			printf("%02x:", eth->ether_dhost[i]);	// print Destination Mac Address
			if((i+1) == (ETHER_ADDR_LEN-1))		// If next i value is last index, print last address value and quit loop.
				printf("%02x", eth->ether_dhost[++i]);
			i++;
		}
		printf("\n");
	}
}

int main()
{
	int num, i = 0;	// num variable get interface number, i variable is only integer variable.
	char str[INET_ADDRSTRLEN];	// This variable used by inet_ntop() function.
	u_int pktCnt = 0;	// Packet Count variable.
	struct pcap_pkthdr *header;
	const u_char *data;			// data pointer variable will have packet content after pcap_next
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_arp_hdr *arp;
	struct libnet_tcp_hdr *tcp;
	struct libnet_udp_hdr *udp;	// Each of struct pointer variable.
	//char file[] = "httpGet.pcap";
	char file[] = "httpEx.pcap";
	//char file[] = "httpPost.pcap";

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_offline(file, errbuf);	// pcap file open!
	
	while((num = pcap_next_ex(pcap, &header, &data)) > 0) {
		eth = (struct libnet_ethernet_hdr*) data;	// eth point to packet's first part.
		if(ntohs(eth->ether_type) == ETHERTYPE_IP)	// IPv4 is '0800' in packet. So check this.
			ip = (struct libnet_ipv4_hdr*) (data + sizeof(struct libnet_ethernet_hdr));	// ip point to part of packet in sequence.
		else if(ntohs(eth->ether_type) == ETHERTYPE_ARP)	// arp is '0806' in packet.
			arp = (struct libnet_arp_hdr*) (data + sizeof(struct libnet_ethernet_hdr));
		else {
			printf("\nIP Error. Please Check ethernet frame.\nCurrent Type : %04x", ntohs(eth->ether_type));
			return -1;
		}
		if(ip->ip_p == IPPROTO_TCP)	// If tcp protocol, continue it.
			tcp = (struct libnet_tcp_hdr*) (data + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));	// tcp point to part of packet in sequence.
		else if(ip->ip_p == IPPROTO_UDP)	// else if udp protocol, continue it.
			udp = (struct libnet_udp_hdr*) (data + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
		else {
			printf("\nTCP Error. Please Check ip packet.\nCurrent protocol : %02x", ip->ip_p);
			return -1;
		}
		
		printf("Packet No .%i\n", ++pktCnt);	// print packet number
		printf("Packet size : %d bytes\n", header->len);	// print packet length
		printf("MAC src: ");	mac_print(i++, eth);
		printf("MAC dest: ");	mac_print(i, eth);
		printf("IP src : %s\n", inet_ntop(AF_INET, &ip->ip_src.S_un.S_addr, str, sizeof(str)));		// print Source IP Address
		printf("IP dest : %s\n", inet_ntop(AF_INET, &ip->ip_dst.S_un.S_addr, str, sizeof(str)));	// print Destination IP Address
		printf("Src port : %d\n", ntohs(tcp->th_sport));	// print Source TCP Port
		printf("Dst port : %d\n", ntohs(tcp->th_dport));	// print Destination TCP Port

		if(header->len != header->caplen)
			printf("Capture size error. Different size : %ld bytes\n", header->len);
		printf("\n\n");
	}
    return 0;
}
