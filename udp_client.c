#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "udp_client.h"
#include "node.h"

#define DEFAULT_OTHER_ADDR_LEN sizeof(struct sockaddr_in6)

void init_chat_with_peer(struct node *peer);
void chat_hp(void *w);

struct LinkedList *peers;

// The client
struct sockaddr_in *sa_me_internal;
char me_internal_ip[256];
char me_internal_port[20];
char me_internal_family[20];
struct sockaddr_in *sa_me_external;
char me_external_ip[256];
char me_external_port[20];
char me_external_family[20];

// The server
struct sockaddr *sa_server;
char server_internal_ip[256];
char server_internal_port[20];
char server_internal_family[20];
socklen_t server_socklen = 0;

// various
int sock_fd;
int chat_sock_fd;

// function pointers
// void (*chat_socket_created)(int) = NULL;
// void (*chat_socket_bound)(void) = NULL;
// void (*chat_sendto_succeeded)(size_t) = NULL;
// void (*chat_recd)(size_t, socklen_t, char *) = NULL;

int node_to_addr(struct sockaddr **addr, struct node n) {
	if (!addr) return -1;

	switch (n.family) {
		case AF_INET: {
			struct sockaddr_in *sai = malloc(sizeof(struct sockaddr_in));
			sai->sin_addr.s_addr = n.ip4;
			sai->sin_port = n.port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sai = malloc(sizeof(struct sockaddr_in6));
			memcpy(sai->sin6_addr.s6_addr, n.ip6, sizeof(unsigned char[16]));
			sai->sin6_port = n.port;
			sai->sin6_family = AF_INET;
			*addr = (struct sockaddr*)&sai;
			(*addr)->sa_family = AF_INET6;
			break;
		}
		default: {
			break;
		}
	}

	return 0;
}

void pfail(char *w) {
	printf("pfail 0\n");
	perror(w);
	exit(1);
}

void punch_hole_in_peer(struct node *peer) {
	if (!peer) return;
	// TODO set peer->status = STATUS_NEW_PEER?
	// and then set back to previous status?
	struct sockaddr peer_addr;
	socklen_t peer_socklen = 0;
	switch (peer->family) {
		case AF_INET: {
			peer_addr.sa_family = AF_INET;
			((struct sockaddr_in *)&peer_addr)->sin_family = AF_INET;
			((struct sockaddr_in *)&peer_addr)->sin_addr.s_addr = peer->ip4;
			((struct sockaddr_in *)&peer_addr)->sin_port = peer->port;
			peer_socklen = sizeof(struct sockaddr_in);
			break;
		}
		case AF_INET6: {
			peer_addr.sa_family = AF_INET6;
			((struct sockaddr_in6 *)&peer_addr)->sin6_family = AF_INET6;
			memcpy(((struct sockaddr_in6 *)&peer_addr)->sin6_addr.s6_addr,
				peer->ip6, sizeof(unsigned char[16]));
			((struct sockaddr_in6 *)&peer_addr)->sin6_port = peer->port;
			peer_socklen = sizeof(struct sockaddr_in6);
			break;
		}
		default: {
			printf("punch_hole_in_peer, peer->family not well defined\n");
			return;
		}
	}
	char pi[256];
	char pp[20];
	char pf[20];
	addr_to_str(&peer_addr, pi, pp, pf);
	printf("punch_hole_in_peer %s %s %s\n", pi, pp, pf);
	if (sendto(sock_fd, peer, sizeof(*peer), 0, &peer_addr, peer_socklen) == -1)
		pfail("punch_hole_in_peer sendto");
}

void ping_all_peers() {
	nodes_perform(peers, punch_hole_in_peer);
}

int wain(void (*self_info)(char *),
		void (*server_info)(char *),
		void (*socket_created)(int),
		void (*socket_bound)(void),
		void (*sendto_succeeded)(size_t),
		void (*recd)(size_t, socklen_t, char *),
		void (*coll_buf)(char *),
		void (*new_client)(char *),
		void (*confirmed_client)(void),
		void (*new_peer)(char *),
		void (*unhandled_response_from_server)(int),
		void (*chat_socket_created)(int),
		void (*chat_socket_bound)(void),
		void (*chat_sendto_succeeded)(size_t),
		void (*chat_recd)(size_t, socklen_t, char *),
		void (*whilew)(int),
		void (*end_while)(void)) {

	printf("main 0 %lu\n", DEFAULT_OTHER_ADDR_LEN);

	// Other (server or peer in recvfrom)
	struct sockaddr sa_other;
	char other_ip[256];
	char other_port[20];
	char other_family[20];
	socklen_t other_socklen = DEFAULT_OTHER_ADDR_LEN;

	// Self
	node_t *self = malloc(sizeof(node_t));
	self->status = STATUS_INIT_NODE;

	// Buffer
	node_t buf;
	char buf_ip[256];

	// Various
	int running = 1;
	size_t sendto_len, recvf_len;
	char sprintf[256];

	// Setup self
	str_to_addr((struct sockaddr**)&sa_me_internal, NULL, "1313", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	addr_to_str((struct sockaddr*)sa_me_internal, me_internal_ip, me_internal_port, me_internal_family);
	sprintf(sprintf, "Moi %s port%s %s", me_internal_ip, me_internal_port, me_internal_family);
	if (self_info) self_info(sprintf);

	// Setup server
	str_to_addr(&sa_server, "142.105.56.124", "9930", AF_INET, SOCK_DGRAM, 0);
	server_socklen = sa_server->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	addr_to_str(sa_server, server_internal_ip, server_internal_port, server_internal_family);
	sprintf(sprintf, "The server %s port%s %s %u",
		server_internal_ip,
		server_internal_port,
		server_internal_family,
		server_socklen);
	if (server_info) server_info(sprintf);

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_fd == -1) {
		printf("There was a problem creating the socket\n");
	} else if (socket_created) socket_created(sock_fd);

	int br = bind(sock_fd, (struct sockaddr*)sa_me_internal, sizeof(*sa_me_internal));
	if ( br == -1 ) pfail("bind");
	if (socket_bound) socket_bound();

	sendto_len = sendto(sock_fd, self, sizeof(node_t), 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded) sendto_succeeded(sendto_len);

	peers = malloc(sizeof(LinkedList));
    memset(peers, '\0', sizeof(LinkedList));

	while (running) {
		recvf_len = recvfrom(sock_fd, &buf, sizeof(buf), 0, &sa_other, &other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_other, other_ip, other_port, other_family);
		sprintf(sprintf, "%s port%s %s", other_ip, other_port, other_family);
		if (recd) recd(recvf_len, other_socklen, sprintf);
		other_socklen = DEFAULT_OTHER_ADDR_LEN;

		struct sockaddr *buf_sa;
		node_to_addr(&buf_sa, buf);
		char bp[20];
		char bf[20];
		addr_to_str(buf_sa, buf_ip, bp, bf);
		sprintf(sprintf, "coll_buf sz:%zu st:%d ip:%s p:%u f:%u",
			sizeof(buf),
			buf.status,
			buf_ip,
			ntohs(buf.port),
			buf.family);
		if (coll_buf) coll_buf(sprintf);

		if (addr_equals(sa_server, &sa_other)) {
			// The datagram came from the server.
			switch (buf.status) {
				case STATUS_NEW_NODE: {
					sa_me_external = malloc(sizeof(struct sockaddr_in));
					memcpy(sa_me_external, buf_sa, sizeof(struct sockaddr_in));
					addr_to_str((struct sockaddr*)sa_me_external,
						me_external_ip,
						me_external_port,
						me_external_family);
					sprintf(sprintf, "Moi aussie %s port%s %s",
						me_external_ip,
						me_external_port,
						me_external_family);
					if (new_client) new_client(sprintf);
					break;
				}
				case STATUS_CONFIRMED_NODE: {
					if (confirmed_client) confirmed_client();
					break;
				}
				case STATUS_NEW_PEER: {
					// The server code is set to send us a datagram for each peer,
					// in which the payload contains the peer's UDP endpoint data.
					// We're receiving binary data here, sent using the server's
					// byte ordering. We should make sure we agree on the
					// endianness in any serious code.
					// Now we just have to add the reported peer into our peer list
					node_t *new_peer_added;
					copy_and_add_tail(peers, &buf, &new_peer_added);
					if (new_peer_added) {
						sprintf(sprintf, "New peer %s p:%u added\nNow we have %d peers",
							buf_ip,
							ntohs(buf.port),
							peers->node_count);
					} else {
						sprintf(sprintf, "New peer %s p:%u already exist\nNow we have %d peers",
							buf_ip,
							ntohs(buf.port),
							peers->node_count);
					}
					if (new_peer) new_peer(sprintf);
                    
					// And here is where the actual hole punching happens. We are going to send
					// a bunch of datagrams to each peer. Since we're using the same socket we
					// previously used to send data to the server, our local endpoint is the same
					// as before.
					// If the NAT maps our local endpoint to the same public endpoint
					// regardless of the remote endpoint, after the first datagram we send, we
					// have an open session (the hole punch) between our local endpoint and the
					// peer's public endpoint. The first datagram will probably not go through
					// the peer's NAT, but since UDP is stateless, there is no way for our NAT
					// to know that the datagram we sent got dropped by the peer's NAT (well,
					// our NAT may get an ICMP Destination Unreachable, but most NATs are
					// configured to simply discard them) but when the peer sends us a datagram,
					// it will pass through the hole punch into our local endpoint.
					for (int j = 0; j < 10; j++) {
						// Send 10 datagrams.
						// printf("punching hole %d\n", j);
						// peers_perform(punch_hole_in_peer);
						punch_hole_in_peer(new_peer_added);
					}
					// init_chat_with_peer(new_peer_added);
					break;
                    
				}
                    
				default: {
					if (unhandled_response_from_server)
						unhandled_response_from_server(buf.status);
					break;
				}
			}
		} else {
			// Then it is from a peer, probably
			printf("FROM PEER: ip:%s port:%s fam:%s\n", other_ip, other_port, other_family);
		}
        free(buf_sa);
	}

	return 0;
}

void init_chat_with_peer(struct node *peer) {
	pthread_t ct;
	int rc = pthread_create(&ct, NULL, chat_hp, (void *) peer);
	if (rc) {
		printf("ERROR; return code from pthread_create() is %d\n", rc);
		return;
	}
}

void chat_hp(void *w) {
	printf("chat_hp\n");

	// int running = 1;

	// chat_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	// if (chat_sock_fd == -1) {
	// 	printf("There was a problem creating the socket\n");
	// } else if (chat_socket_created) chat_socket_created(chat_sock_fd);

	// int br = bind(chat_sock_fd, (struct sockaddr*)sa_me_internal, sizeof(*sa_me_internal));
	// if ( br == -1 ) pfail("bind");
	// if (chat_socket_bound) chat_socket_bound();

//	size_t sendto_len = sendto(chat_sock_fd, self, sizeof(node), 0, sa_server, server_socklen);
//	if (sendto_len == -1) {
//		char w[256];
//		sprintf(w, "sendto failed with %zu", sendto_len);
//		pfail(w);
//	} else if (chat_sendto_succeeded) chat_sendto_succeeded(sendto_len);
//
//	while (running) {
//	}
}
