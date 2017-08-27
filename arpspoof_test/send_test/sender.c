#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <pcap.h>
#include <libnet\include\libnet\libnet-headers.h>
#define PORT 6666
#define DEST_ADDR "192.168.219.255"

int main(int argc, char *argv[]) {
	SOCKET sock;
	WSADATA wsaData;
	int num, broadcast = 1;
	struct sockaddr_in send, recv;

	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return 1;
	}

	if((sock = socket(PF_INET,SOCK_DGRAM,0)) == -1) {
		perror("Socket Error!!");
		exit(1);
	}

	if((setsockopt(sock,SOL_SOCKET,SO_BROADCAST, (const char*)&broadcast,sizeof broadcast)) == -1) {
		perror("Setsockopt Error - SO_SOCKET ");
		exit(1);
	}

	send.sin_family = AF_INET;
	send.sin_port = PORT;
	send.sin_addr.s_addr = INADDR_ANY;
	memset(send.sin_zero,'\0',sizeof send.sin_zero);

	if(bind(sock, (struct sockaddr*) &send, sizeof send) == -1) {
		perror("Bind Error!!");
		exit(1);
	}

	recv.sin_family = AF_INET;
	recv.sin_port = PORT;
	recv.sin_addr.s_addr = inet_addr(DEST_ADDR);
	memset(recv.sin_zero,'\0',sizeof recv.sin_zero);

	while((num = sendto(sock, "abcd", 4 , 0, (struct sockaddr *)&recv, sizeof recv)) != -1) {
   		printf("Sent a packet...\n");
   		Sleep(1000);
	}
	perror("Send to");
	exit(1);

	closesocket(sock);
	WSACleanup();
	return 0;
}