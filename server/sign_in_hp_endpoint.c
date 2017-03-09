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
socklen_t slen = SZ_SOCKADDR;
// TODO I should probably add separate socklen_t for recvfrom
// since that function can apparently change this value
LinkedList_t *nodes;

void pfail(char *s) {
	perror(s);
	exit(1);
}

void notify_existing_peer_of_new_tail(node_t *existing_peer) {
	// We don't want to notify the new peer (i.e. nodes->tail) of itself.
	// That is to say, if existing_peer->next is NULL, then we are at the
	// tail... so don't do this.
	if (!existing_peer || !existing_peer->next) return;

	// Let's get the sockaddr of existing_peer
	struct sockaddr ep_addr;
	switch (existing_peer->external_family) {
		case AF_INET: {
			ep_addr.sa_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_port = existing_peer->external_port;
			((struct sockaddr_in*)&ep_addr)->sin_addr.s_addr = existing_peer->external_ip4;
			break;
		}
		case AF_INET6: {
			ep_addr.sa_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_port = existing_peer->external_port;
			memcpy(((struct sockaddr_in6*)&ep_addr)->sin6_addr.s6_addr, existing_peer->external_ip6, 16);
			break;
		}
		default: return;
	}

	node_buf_t *exip_node_buf;
	node_buf_t *tail_node_buf;
	get_approp_node_bufs(existing_peer, nodes->tail, &exip_node_buf, &tail_node_buf);

	// And now we notify existing peer of new tail
	if (sendto(sock_fd, tail_node_buf, SZ_NODE_BF, 0, &ep_addr, slen)==-1)
		pfail("sendto");

	// And notify new tail (i.e. si_other) of existing peer
	if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, &si_other, slen)==-1)
		pfail("sendto");

	free(exip_node_buf);
	free(tail_node_buf);
}

void *sign_in_endpoint(void *msg) {
	printf("sign_in_endpoint 0 %s %zu %zu %zu %zu\n", (char *)msg,
		SZ_NODE, sizeof(node_t),
		SZ_NODE_BF, sizeof(node_buf_t));

	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	node_buf_t buf;
	nodes = malloc(SZ_LINK_LIST);
	memset(nodes, '\0', SZ_LINK_LIST);

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
		recvf_len = recvfrom(sock_fd, &buf, SZ_NODE_BF, 0, &si_other, &slen);
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
				// TODO We must add a check here to see if this new node
				// already exists in our linked list. If so, how to 
				// handle that?
				node_t *new_tail;
				get_new_tail(nodes, &new_tail);
				new_tail->status = STATUS_NEW_NODE;
				switch (si_other.sa_family) {
					case AF_INET: {
						struct sockaddr_in *sai4 = (struct sockaddr_in*)&si_other;
						new_tail->external_ip4 = sai4->sin_addr.s_addr;
						new_tail->external_port = sai4->sin_port;
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6 *sai6 = (struct sockaddr_in6*)&si_other;
						memcpy(new_tail->external_ip6, sai6->sin6_addr.s6_addr, 16);
						new_tail->external_port = sai6->sin6_port;
						break;
					}
					default: {
						printf("We received STATUS_INIT_NODE with invalid family %d\n",
							si_other.sa_family);
						continue;
					}
				}
				new_tail->external_family = si_other.sa_family;
				node_buf_t *new_tail_buf;
				node_external_to_node_buf(new_tail, &new_tail_buf);
				sendto_len = sendto(sock_fd, new_tail_buf, SZ_NODE_BF, 0, &si_other, slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				printf("Sendto %zu %d\n", sendto_len, new_tail->external_family);
				// TODO do we really need STATUS_CONFIRMED_NODE?
				// if so, then we need to code node to send confirmation
				// and add a case here to set STATUS_CONFIRMED_NODE
				// for now, we'll just set it here
				new_tail->status = STATUS_CONFIRMED_NODE;
				// Now we set the status to new peer so that when the
				// peers recv the sendto's below, they know they are
				// getting a new peer
				new_tail->status = STATUS_NEW_PEER;
				// And now we notify all peers of new peer as
				// well as notify new peer of existing peers
				nodes_perform(nodes, notify_existing_peer_of_new_tail);
				break;
			}
			case STATUS_STAY_IN_TOUCH: {
				printf("Stay in touch from %s port%d %d %d\n", ip_str, port, family, STATUS_STAY_IN_TOUCH_RESPONSE);
				buf.status = STATUS_STAY_IN_TOUCH_RESPONSE;
				sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, &si_other, slen);
				if (sendto_len == -1) {
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

		printf("Now we have %d nodes\n", nodes->node_count);
		// And we go back to listening. Notice that since UDP has no notion
        	// of connections, we can use the same socket to listen for data
        	// from different clients.
	}

	close(sock_fd);
	free_list(nodes);
	pthread_exit("sign_in_thread exiting normally");
}

int main() {
	printf("sign_in_hp_endpoint main 0 %zu %zu\n", sizeof(STATUS_TYPE), sizeof(struct node));
	char *thread_exit_msg;
	int pcr = pthread_create(&sign_in_thread, NULL, sign_in_endpoint, (void *)"sign_in_thread");
	if (pcr) {
		printf("ERROR starting sign_in_thread: %d\n", pcr);
		exit(-1);
	} else {
		pthread_join(sign_in_thread,(void**)&thread_exit_msg);
	}

	printf("Wrapping up sign_in_service: %s\n", thread_exit_msg);
	return 0;
}