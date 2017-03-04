#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include "node.h"
#include "network_utils.h"
 
#define BUFLEN 512
#define NPACK 10
#define PORT 9930

int sign_in_running = 1;
pthread_t sign_in_thread;
int sock_fd;
struct sockaddr si_other;
socklen_t slen = sizeof(struct sockaddr);
LinkedList *nodes;

void pfail(char *s) {
	perror(s);
	exit(1);
}

void notify_peers_of_new_peer(node_t *existing_peer) {
	// We don't want to notify the new peer (i.e. nodes->tail) of itself
	if (!existing_peer || !existing_peer->next) return;

	struct sockaddr w_addr;
	switch (existing_peer->family) {
		case AF_INET: {
			w_addr.sa_family = AF_INET;
			((struct sockaddr_in*)&w_addr)->sin_family = AF_INET;
			((struct sockaddr_in*)&w_addr)->sin_port = existing_peer->port;
			((struct sockaddr_in*)&w_addr)->sin_addr.s_addr = existing_peer->ip4;
			break;
		}
		case AF_INET6: {
			w_addr.sa_family = AF_INET6;
			((struct sockaddr_in6*)&w_addr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)&w_addr)->sin6_port = existing_peer->port;
			memcpy(((struct sockaddr_in6*)&w_addr)->sin6_addr.s6_addr, existing_peer->ip6, 16);
			break;
		}
		default: return;
	}

	if (sendto(sock_fd, nodes->tail, sizeof(node_t), 0, &w_addr, slen)==-1)
		pfail("sendto");

	if (sendto(sock_fd, existing_peer, sizeof(node_t), 0, (struct sockaddr*)(&si_other), slen)==-1)
		pfail("sendto");
}

void *sign_in_endpoint(void *msg) {
	printf("sign_in_endpoint 0 %s\n", (char *)msg);

	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	struct node buf;
	nodes = malloc(sizeof(LinkedList));
	memset(nodes, '\0', sizeof(LinkedList));
	// struct node nodes[10]; // 10 clients. Notice that we're not doing any bound checking.
	// int num_nodes = 0;

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sock_fd == -1 ) pfail("socket");
	printf("sign_in_endpoint 1 %d\n", sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	str_to_addr((struct sockaddr**)&si_me, NULL, "9930", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	printf("sign_in_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("bind");
	printf("sign_in_endpoint 3 %d\n", br);

	while (sign_in_running) {
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
				node_t *new_tail;
				get_new_tail(nodes, &new_tail);
				new_tail->status = STATUS_NEW_NODE;
				switch (si_other.sa_family) {
					case AF_INET: {
						struct sockaddr_in *sai4 = (struct sockaddr_in*)&si_other;
						new_tail->ip4 = sai4->sin_addr.s_addr;
						new_tail->port = sai4->sin_port;
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6 *sai6 = (struct sockaddr_in6*)&si_other;
						memcpy(new_tail->ip6, sai6->sin6_addr.s6_addr, 16);
						new_tail->port = sai6->sin6_port;
						break;
					}
					default: {
						printf("We received STATUS_INIT_NODE with invalid family %d\n",
							si_other.sa_family);
						continue;
					}
				}
				new_tail->family = si_other.sa_family;
				sendto_len = sendto(sock_fd, new_tail, sizeof(node_t), 0, (struct sockaddr*)(&si_other), slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				printf("Sendto %zu %d\n", sendto_len, new_tail->family);
				// TODO do we really need STATUS_CONFIRMED_NODE?
				// if so, then we need to code node to send confirmation
				// and add a case here to set STATUS_CONFIRMED_NODE
				// for now, we'll just set it here
				new_tail->status = STATUS_CONFIRMED_NODE;
				// Now we set the status to new peer so that when the
				// peers recv the sendto's below, they know they are
				// getting a new peer
				new_tail->status = STATUS_NEW_PEER;

				nodes_perform(nodes, notify_peers_of_new_peer);
				break;
			}
			default: {
				char *buf_char = (char *) &buf;
				printf("None of the above - buf.status -: %d -: %s\n", buf.status, buf_char);
				break;
			}
		}

		printf("Now we have %d nodes\n", nodes->node_count);
		// And we go back to listening. Notice that since UDP has no notion
        	// of connections, we can use the same socket to listen for data
        	// from different clients.
	}

	close(sock_fd);
	pthread_exit("sign_in_thread exiting normally");
}

int main() {
	printf("main 0 %zu %zu\n", sizeof(STATUS_TYPE), sizeof(struct node));
	char *thread_exit_msg;
	int pcr = pthread_create(&sign_in_thread, NULL, sign_in_endpoint, (void *)"sign_in_thread");
	if (pcr) {
		printf("ERROR start sign_in_thread: %d\n", pcr);
		exit(-1);
	} else {
		pthread_join(sign_in_thread,(void**)&thread_exit_msg);
	}

	printf("Wrapping up sign_in_service: %s\n", thread_exit_msg);
	return 0;
}