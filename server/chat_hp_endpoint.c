#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "network_utils.h"
#include "common.h"

int chat_running = 1;
pthread_t chat_thread;
int sock_fd;

void pfail(char *s) {
	perror(s);
	exit(1);
}

void *chat_endpoint(void *msg) {
	printf("chat_endpoint 0 %s\n", (char *)msg);

	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	chat_buf_t buf;
	struct sockaddr si_other;
	socklen_t slen = sizeof(struct sockaddr);

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sock_fd == -1 ) pfail("socket");
	printf("chat_endpoint 1 %d\n", sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	str_to_addr((struct sockaddr**)&si_me, NULL, "9931", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	printf("chat_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("bind");
	printf("chat_endpoint 3 %d\n", br);

	while (chat_running) {
		recvf_len = recvfrom(sock_fd, &buf, sizeof(buf), 0, &si_other, &slen);
		if ( recvf_len == -1) pfail("recvfrom");

		char ip_str[INET6_ADDRSTRLEN];
		unsigned short port;
		unsigned short family;
		// void *addr = &(si_other.sin_addr);
		// inet_ntop( AF_INET, &(si_other.sin_addr), ip_str, sizeof(ip_str) );
		addr_to_str_short( &si_other, ip_str, &port, &family );
		printf("Received packet (%zu bytes) from %s port%d %d\n", recvf_len, ip_str, port, family);

		// TODO we should probably handle packets with a thread pool
		// so that the next recvfrom isn't blocked by the below code
		switch(buf.status) {
			case CHAT_STATUS_INIT: {
				buf.status = CHAT_STATUS_NEW_CHAT_HP;
				buf.family = si_other.sa_family;
				switch (si_other.sa_family) {
					case AF_INET: {
						buf.ip4 = ((struct sockaddr_in *)&si_other)->sin_addr.s_addr;
						buf.port = ((struct sockaddr_in *)&si_other)->sin_port;
						break;
					}
					case AF_INET6: {
						memcpy(buf.ip6, ((struct sockaddr_in6 *)&si_other)->sin6_addr.s6_addr,
							sizeof(unsigned char[16]));
						buf.port = ((struct sockaddr_in6 *)&si_other)->sin6_port;
						break;
					}
					default: {
						printf("CHAT_STATUS_INIT si_other.sa_family is not good %d\n",
							si_other.sa_family);
						continue;
					}
				}
				sendto_len = sendto(sock_fd, &buf, sizeof(buf), 0, &si_other, slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				printf("Sendto %zu %d\n", sendto_len, buf.family);
				break;
			}
			default: {
				break;
			}
		}
	}

	pthread_exit("chat_hp_thread exiting normally");
}

int main() {
	printf("chat_hp_endpoint main 0\n");
	char *thread_exit_msg;
	int pcr = pthread_create(&chat_thread, NULL, chat_endpoint, (void *)"chap_hp_thread");
	if (pcr) {
		printf("ERROR starting chat_hp_thread: %d\n", pcr);
		exit(-1);
	} else {
		pthread_join(chat_thread,(void**)&thread_exit_msg);
	}

	printf("Wrapping up chat_service: %s\n", thread_exit_msg);
	return 0;
}