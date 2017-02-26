#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "udp_client.h"
#include "network_utils.h"

#define DEFAULT_OTHER_ADDR_LEN sizeof(struct sockaddr_in6)

typedef enum STATUS_TYPE {
    STATUS_INIT_NODE = 0,
    STATUS_NEW_NODE = 1,
    STATUS_CONFIRMED_NODE = 2,
    STATUS_NEW_PEER = 3 // A peer is any client other than self
} STATUS_TYPE;

typedef struct node {
	STATUS_TYPE status;
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short family;
} node;

void pfail(char *w) {
	printf("pfail 0\n");
	perror(w);
	exit(1);
}

int wain(void (*will_connect_server)(void),
		void (*looping_recv)(void),
		void (*recd)(char *),
		void (*new_client)(char *),
		void (*confirmed_client)(void),
		void (*new_peer)(char *),
		void (*unhandled_response_from_server)(int),
		void (*whilew)(int),
		void (*end_while)(void)) {

	printf("main 0 %lu\n", DEFAULT_OTHER_ADDR_LEN);

	// The client
	struct sockaddr_in *sa_me;
	char me_internal_ip[256];
	char me_internal_port[20];
	char me_internal_family[20];

	// The server
	struct sockaddr *sa_server;
	char server_internal_ip[256];
	char server_internal_port[20];
	char server_internal_family[20];
	socklen_t server_socklen = 0;

	// Other (server or peer in recvfrom)
	struct sockaddr sa_other;
	char other_ip[256];
	char other_port[20];
	char other_family[20];
	socklen_t other_socklen = DEFAULT_OTHER_ADDR_LEN;

	// Self
	node *self = malloc(sizeof(node));
	self->status = STATUS_INIT_NODE;

	// Buffer
	node buf;
	char buf_ip[256];

	// Various
	int running = 1;
	size_t sendto_len, recvf_len;

	// Setup self
	str_to_addr((struct sockaddr**)&sa_me, NULL, "1313", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	addr_to_str((struct sockaddr*)sa_me, me_internal_ip, me_internal_port, me_internal_family);
	printf("Moi %s port%s %s\n", me_internal_ip, me_internal_port, me_internal_family);

	// Setup server
	str_to_addr(&sa_server, "142.105.56.124", "9930", AF_INET, SOCK_DGRAM, 0);
	server_socklen = sa_server->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	addr_to_str(sa_server, server_internal_ip, server_internal_port, server_internal_family);
	printf("The server %s port%s %s %u\n",
		server_internal_ip,
		server_internal_port,
		server_internal_family,
		server_socklen);

	int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_fd == -1) {
		printf("There was a problem creating the socket\n");
	} else {
		printf("The socket file descriptor is %d\n", sock_fd);
    }
    
    int br = bind(sock_fd, (struct sockaddr*)sa_me, sizeof(*sa_me));
    if ( br == -1 ) pfail("bind");
    printf("bind succeeded %d\n", br);

	sendto_len = sendto(sock_fd, self, sizeof(node), 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else {
		printf("sendto succeeded, %zu bytes sent\n", sendto_len);
	}

	while (running) {
		recvf_len = recvfrom(sock_fd, &buf, sizeof(buf), 0, &sa_other, &other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_other, other_ip, other_port, other_family);
		printf("recvfrom %zu %u %s port%s %s\n", recvf_len, other_socklen, other_ip, other_port, other_family);
		other_socklen = DEFAULT_OTHER_ADDR_LEN;

		struct sockaddr bufsa;
		switch (buf.family) {
			case AF_INET: {
				printf("Gathering buf data for IPv4\n");
				struct sockaddr_in sai;
				sai.sin_addr.s_addr = buf.ip4;
				bufsa = *(struct sockaddr*)&sai;
				bufsa.sa_family = AF_INET;
				break;
			}
			case AF_INET6: {
				printf("Gathering buf data for IPv6\n");
				struct sockaddr_in6 sai;
				memcpy(sai.sin6_addr.s6_addr, buf.ip6, sizeof(unsigned char[16]));
				bufsa = *(struct sockaddr*)&sai;
				bufsa.sa_family = AF_INET6;
				break;
			}
			default: {
				break;
			}
		}
		char bp[20];
		char bf[20];
		addr_to_str(&bufsa, buf_ip, bp, bf);
		size_t bufsz = sizeof(buf);
		printf("buf %zu %d %s port%u %u\n", bufsz, buf.status, buf_ip, ntohs(buf.port), buf.family);
	}

	return 0;
}
