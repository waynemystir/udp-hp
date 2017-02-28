#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "network_utils.h"
 
#define BUFLEN 512
#define NPACK 10
#define PORT 9930

typedef enum STATUS_TYPE {
    STATUS_INIT_NODE = 0,
    STATUS_NEW_NODE = 1,
    STATUS_CONFIRMED_NODE = 2,
    STATUS_NEW_PEER = 3 // A peer is any node other than self
} STATUS_TYPE;

struct node {
	STATUS_TYPE status;
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short family;
	struct node *next;
};

void pfail(char *s) {
	perror(s);
	exit(1);
}

int main() {
	printf("main 0 %zu %zu\n", sizeof(STATUS_TYPE), sizeof(struct node));

	int running = 1;
	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	struct sockaddr si_other;
	socklen_t slen = sizeof(struct sockaddr);
	int sock_fd;
	struct node buf;
	struct node nodes[10]; // 10 clients. Notice that we're not doing any bound checking.
	int num_nodes = 0;

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sock_fd == -1 ) pfail("socket");
	printf("main 1 %d\n", sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	str_to_addr((struct sockaddr**)&si_me, NULL, "9930", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	printf("main 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("bind");
	printf("main 3 %d\n", br);

	while (running) {
		// printf("main -: 3\n");
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
			case STATUS_INIT_NODE: {
				printf("New node %s %d\n", ip_str, port);
				nodes[num_nodes].status = STATUS_NEW_NODE;
				switch (si_other.sa_family) {
					case AF_INET: {
						struct sockaddr_in *sai4 = (struct sockaddr_in*)&si_other;
						nodes[num_nodes].ip4 = sai4->sin_addr.s_addr;
						nodes[num_nodes].port = sai4->sin_port;
						nodes[num_nodes].next = NULL;
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6 *sai6 = (struct sockaddr_in6*)&si_other;
						memcpy(nodes[num_nodes].ip6, sai6->sin6_addr.s6_addr, 16);
						nodes[num_nodes].port = sai6->sin6_port;
						nodes[num_nodes].next = NULL;
						break;
					}
					default:
						printf("We received STATUS_INIT_NODE with invalid family %d\n",
							si_other.sa_family);
				}
				nodes[num_nodes].family = si_other.sa_family;
				int n1 = num_nodes++;
				sendto_len = sendto(sock_fd, &nodes[n1], sizeof(nodes[n1]), 0, (struct sockaddr*)(&si_other), slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				printf("Sendto %zu %d\n", sendto_len, nodes[n1].family);
				// TODO do we really need STATUS_CONFIRMED_NODE?
				// if so, then we need to code node to send confirmation
				// and add a case here to set STATUS_CONFIRMED_NODE
				// for now, we'll just set it here
				nodes[n1].status = STATUS_CONFIRMED_NODE;
				// Now we set the status to new peer so that when the
				// peers recv the sendto's below, they know they are
				// getting a new peer
				nodes[n1].status = STATUS_NEW_PEER;

				for (int w = 0; w < n1; w++) {

					struct sockaddr w_addr;
					switch (nodes[w].family) {
						case AF_INET: {
							w_addr.sa_family = AF_INET;
							((struct sockaddr_in*)&w_addr)->sin_family = AF_INET;
							((struct sockaddr_in*)&w_addr)->sin_port = nodes[w].port;
							((struct sockaddr_in*)&w_addr)->sin_addr.s_addr = nodes[w].ip4;
							break;
						}
						case AF_INET6: {
							w_addr.sa_family = AF_INET6;
							((struct sockaddr_in6*)&w_addr)->sin6_family = AF_INET6;
							((struct sockaddr_in6*)&w_addr)->sin6_port = nodes[w].port;
							memcpy(((struct sockaddr_in6*)&w_addr)->sin6_addr.s6_addr, nodes[w].ip6, 16);
							break;
						}
						default: continue;
					}
					if (sendto(sock_fd, &nodes[(n1)], sizeof(nodes[(n1)]), 0, &w_addr, slen)==-1)
						pfail("sendto");

					if (sendto(sock_fd, &nodes[w], sizeof(nodes[w]), 0, (struct sockaddr*)(&si_other), slen)==-1)
						pfail("sendto");
				}
				break;
			}
			default: {
				char *buf_char = (char *) &buf;
				printf("None of the above - buf.status -: %d -: %s\n", buf.status, buf_char);
				break;
			}
		}

		printf("Now we have %d nodes\n", num_nodes);
		// And we go back to listening. Notice that since UDP has no notion
        	// of connections, we can use the same socket to listen for data
        	// from different clients.
	}

	close(sock_fd);
	return 0;
}