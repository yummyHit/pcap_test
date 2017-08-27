#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>
#include <errno.h>
#include <libnet\include\libnet\libnet-headers.h>
#define PORT 6666
#define DEST_ADDR "192.168.219.100" //Server addr

int main(int argc, char *argv[]) {
	SOCKET sock;
	WSADATA wsaData;
	int num, addr_len, broadcast = 1;
	char buf[100] = {"",};
	struct hostent *he;
	struct sockaddr_in send;

	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return 1;
	}

	if((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket Error!!");
		exit(1);
	}
	printf("Socket Created\n");
/*
	if((setsockopt(sock,SOL_SOCKET,SO_BROADCAST, (const char*)&broadcast,sizeof broadcast)) == -1) {
		perror("Setsockopt Error - SO_SOCKET ");
		exit(1);
	}
*/
	if ((he=gethostbyname(DEST_ADDR)) == NULL) {   // get the host info
		perror("Gethostbyname Error");
   		exit(1);
	}
 	printf("Host Found\n");
 
	send.sin_family = AF_INET;
	send.sin_port = PORT;
	send.sin_addr = *((struct in_addr *)he->h_addr);
	memset(send.sin_zero,'\0', sizeof(send.sin_zero));

	addr_len = sizeof(send);

	if ((num = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&send, (socklen_t *)&addr_len)) > 0) {
		perror("Receive Error!");
		exit(1);
	}
	printf("%s",buf);

	WSACleanup();
	return 0;
}