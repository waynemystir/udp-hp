#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "udp_client.h"
#include "node.h"
#include "common.h"

#define DEFAULT_OTHER_ADDR_LEN sizeof(struct sockaddr_in6)

void send_hole_punch(node_min_t *peer);
void init_chat_hp();
void *chat_hp_server(void *w);

LinkedList_min_t *peers;

// Self
node_buf_t *self_internal;
node_buf_t *self_external;
struct sockaddr *sa_self_internal;
size_t sz_sa_self_internal;
char self_internal_ip[INET6_ADDRSTRLEN];

// Me
struct sockaddr *sa_me_internal;
char me_internal_ip[INET6_ADDRSTRLEN];
unsigned short me_internal_port;
unsigned short me_internal_family;
struct sockaddr *sa_me_external;
char me_external_ip[INET6_ADDRSTRLEN];
char me_external_port[20];
char me_external_family[20];
struct sockaddr *sa_me_chat;
struct sockaddr *sa_me_chat_external;
char me_chat_ip[INET6_ADDRSTRLEN];
char me_chat_port[20];
char me_chat_family[20];

// The server
struct sockaddr *sa_server;
char server_internal_ip[INET6_ADDRSTRLEN];
char server_internal_port[20];
char server_internal_family[20];
socklen_t server_socklen = 0;

// The chat server
struct sockaddr *sa_chat_server;
char chat_server_internal_ip[INET6_ADDRSTRLEN];
char chat_server_internal_port[20];
char chat_server_internal_family[20];
socklen_t chat_server_socklen = 0;

// The socket file descriptors
int sock_fd;
int chat_sock_fd;

// Runnings
int stay_in_touch_running = 1;
int chat_stay_in_touch_running = 1;
int chat_server_conn_running = 1;

// function pointers
void (*self_info_cb)(char *, unsigned short, unsigned short, unsigned short) = NULL;
void (*server_info_cb)(char *) = NULL;
void (*socket_created_cb)(int) = NULL;
void (*socket_bound_cb)(void) = NULL;
void (*sendto_succeeded_cb)(size_t) = NULL;
void (*recd_cb)(size_t, socklen_t, char *) = NULL;
void (*stay_touch_recd_cb)(SERVER_TYPE) = NULL;
void (*coll_buf_cb)(char *) = NULL;
void (*new_client_cb)(SERVER_TYPE, char *) = NULL;
void (*hole_punch_sent_cb)(char *, int) = NULL;
void (*confirmed_peer_while_punching_cb)(void) = NULL;
void (*from_peer_cb)(char *) = NULL;

int chatbuf_to_addr(struct sockaddr **addr, unsigned short *port, chat_buf_t n) {
	if (!addr) return -1;

	switch (n.family) {
		case AF_INET: {
			struct sockaddr_in *sai = malloc(sizeof(struct sockaddr_in));
			sai->sin_addr.s_addr = n.ip4;
			sai->sin_port = n.port;
			port = &n.port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sai = malloc(sizeof(struct sockaddr_in6));
			memcpy(sai->sin6_addr.s6_addr, n.ip6, sizeof(unsigned char[16]));
			sai->sin6_port = n.port;
			port = &n.port;
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

void *hole_punch_thread(void *peer_to_hole_punch) {
	node_min_t *peer = (node_min_t *)peer_to_hole_punch;
	for (int j = 0; j < 1000; j++) {
		// Send 1000 datagrams, or until the peer
		// is confirmed, whichever occurs first.
		if (peer->status >= STATUS_CONFIRMED_PEER) {
			if (confirmed_peer_while_punching_cb)
				confirmed_peer_while_punching_cb();
			break;
		}
		send_hole_punch(peer);
		usleep(10*1000); // 10 milliseconds
	}
	pthread_exit("hole_punch_thread exiting normally");
}

void punch_hole_in_peer(node_min_t *peer) {
	pthread_t hpt;
	int pt = pthread_create(&hpt, NULL, hole_punch_thread, peer);
	if (pt) {
		printf("ERROR in punch_hole_in_peer; return code from pthread_create() is %d\n", pt);
		return;
	}
}

void send_hole_punch(node_min_t *peer) {
	if (!peer) return;
	// TODO set peer->status = STATUS_NEW_PEER?
	// and then set back to previous status?
	static int hpc = 0;
	struct sockaddr peer_addr;
	socklen_t peer_socklen = 0;
	switch (peer->family) {
		case AF_INET: {
			peer_addr.sa_family = AF_INET;
			((struct sockaddr_in *)&peer_addr)->sin_family = AF_INET;
			((struct sockaddr_in *)&peer_addr)->sin_addr.s_addr = peer->ip4;
			((struct sockaddr_in *)&peer_addr)->sin_port = peer->port;
			peer_socklen = SZ_SOCKADDR_IN;
			break;
		}
		case AF_INET6: {
			peer_addr.sa_family = AF_INET6;
			((struct sockaddr_in6 *)&peer_addr)->sin6_family = AF_INET6;
			memcpy(((struct sockaddr_in6 *)&peer_addr)->sin6_addr.s6_addr,
				peer->ip6, sizeof(unsigned char[16]));
			((struct sockaddr_in6 *)&peer_addr)->sin6_port = peer->port;
			peer_socklen = SZ_SOCKADDR_IN6;
			break;
		}
		default: {
			printf("send_hole_punch, peer->family not well defined\n");
			return;
		}
	}
	if (sendto(sock_fd, peer, SZ_NODE_MN, 0, &peer_addr, peer_socklen) == -1)
		pfail("send_hole_punch sendto");
	char spf[256];
	char pi[INET6_ADDRSTRLEN];
	char pp[20];
	char pf[20];
	addr_to_str(&peer_addr, pi, pp, pf);
	sprintf(spf, "send_hole_punch %s %s %s\n", pi, pp, pf);
	if (hole_punch_sent_cb) hole_punch_sent_cb(spf, ++hpc);
}

void ping_all_peers() {
	nodes_min_perform(peers, send_hole_punch);
}

void *stay_in_touch_with_server_thread(void *msg) {
	printf("stay_in_touch_with_server_thread %s\n", (char*)msg);
	stay_in_touch_running = 1;
	node_min_t w;
	w.status = STATUS_STAY_IN_TOUCH;

	while (stay_in_touch_running) {
		if (sendto(sock_fd, &w, SZ_NODE_MN, 0, sa_server, server_socklen) == -1)
		 	pfail("stay_in_touch_with_server_thread sendto");
		sleep(30); // 30 seconds
	}
	pthread_exit("stay_in_touch_with_server_thread exited normally");
}

void *stay_in_touch_with_chat_server_thread(void *msg) {
	printf("stay_in_touch_with_chat_server_thread %s\n", (char*)msg);
	chat_stay_in_touch_running = 1;
	chat_buf_t w;
	w.status = CHAT_STATUS_STAY_IN_TOUCH;

	while (chat_stay_in_touch_running) {
		if (sendto(chat_sock_fd, &w, sizeof(chat_buf_t), 0, sa_chat_server, chat_server_socklen) == -1)
		 	pfail("stay_in_touch_with_chat_server_thread sendto");
		sleep(30); // 30 seconds
	}
	pthread_exit("stay_in_touch_with_chat_server_thread exited normally");
}

void stay_in_touch_with_server(SERVER_TYPE st) {
	pthread_t sitt;
	char *w = "stay_in_touch_with_server";
	void *start_routine = NULL;
	switch (st) {
		case SERVER_SIGNIN: {
			start_routine = stay_in_touch_with_server_thread;
			break;
		}
		case SERVER_CHAT: {
			start_routine = stay_in_touch_with_chat_server_thread;
			break;
		}
		default: return;
	}
	int pr = pthread_create(&sitt, NULL, start_routine, (void *)w);
	if (pr) {
		printf("ERROR in stay_in_touch_with_server; return code from pthread_create() is %d\n", pr);
		return;
	}
}

int wain(void (*self_info)(char *, unsigned short, unsigned short, unsigned short),
		void (*server_info)(char *),
		void (*socket_created)(int),
		void (*socket_bound)(void),
		void (*sendto_succeeded)(size_t),
		void (*recd)(size_t, socklen_t, char *),
		void (*coll_buf)(char *),
		void (*new_client)(SERVER_TYPE, char *),
		void (*confirmed_client)(void),
		void (*stay_touch_recd)(SERVER_TYPE),
		void (*new_peer)(char *),
		void (*hole_punch_sent)(char *, int),
		void (*confirmed_peer_while_punching)(void),
		void (*from_peer)(char *),
		void (*unhandled_response_from_server)(int),
		void (*whilew)(int),
		void (*end_while)(void)) {

	printf("main 0 %lu\n", DEFAULT_OTHER_ADDR_LEN);
	self_info_cb = self_info;
	server_info_cb = server_info;
	socket_created_cb = socket_created;
	socket_bound_cb = socket_bound;
	sendto_succeeded_cb = sendto_succeeded;
	recd_cb = recd;
	stay_touch_recd_cb = stay_touch_recd;
	coll_buf_cb = coll_buf;
	new_client_cb = new_client;
	hole_punch_sent_cb = hole_punch_sent;
	confirmed_peer_while_punching_cb = confirmed_peer_while_punching;
	from_peer_cb = from_peer;

	// Other (server or peer in recvfrom)
	struct sockaddr sa_other;
	char other_ip[INET6_ADDRSTRLEN];
	char other_port[20];
	char other_family[20];
	socklen_t other_socklen = DEFAULT_OTHER_ADDR_LEN;

	// Self
	get_if_addr(&sa_self_internal, &sz_sa_self_internal, self_internal_ip);
	addr_to_node_buf(sa_self_internal, &self_internal, STATUS_INIT_NODE, 0);

	// Buffer
	node_buf_t buf;
	char buf_ip[INET6_ADDRSTRLEN];

	// Various
	int running = 1;
	size_t sendto_len, recvf_len;
	char sprintf[256];

	// Setup self
	// str_to_addr((struct sockaddr**)&sa_me_internal, NULL, "1313", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	// addr_to_str((struct sockaddr*)sa_me_internal, me_internal_ip, me_internal_port, me_internal_family);
	// sprintf(sprintf, "Moi %s port%s %s", me_internal_ip, me_internal_port, me_internal_family);
	// if (self_info) self_info(sprintf);
	struct sockaddr_in si_me;
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(0);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_me_internal = (struct sockaddr*)&si_me;

	// Setup server
	str_to_addr(&sa_server, "142.105.56.124", "9930", AF_INET, SOCK_DGRAM, 0);
	server_socklen = sa_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
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

	int br = bind(sock_fd, sa_me_internal, sizeof(*sa_me_internal));
	if ( br == -1 ) pfail("bind");
	if (socket_bound) socket_bound();

	socklen_t gsn_len = sizeof(*sa_me_internal);
	int gsn = getsockname(sock_fd, sa_me_internal, &gsn_len);
	if (gsn == -1) pfail("getsockname");

	addr_to_str_short(sa_me_internal, me_internal_ip, &me_internal_port, &me_internal_family);
	sprintf(sprintf, "Moi %s %s", me_internal_ip, self_internal_ip);
	if (self_info_cb) self_info_cb(sprintf, me_internal_port, -1, me_internal_family);
	self_internal->port = me_internal_port;

	sendto_len = sendto(sock_fd, self_internal, SZ_NODE_MN, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded) sendto_succeeded(sendto_len);

	peers = malloc(SZ_LINK_LIST_MN);
	memset(peers, '\0', SZ_LINK_LIST_MN);

	while (running) {
		recvf_len = recvfrom(sock_fd, &buf, SZ_NODE_MN, 0, &sa_other, &other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_other, other_ip, other_port, other_family);
		sprintf(sprintf, "%s port%s %s", other_ip, other_port, other_family);
		if (recd) recd(recvf_len, other_socklen, sprintf);
		other_socklen = DEFAULT_OTHER_ADDR_LEN;

		struct sockaddr *buf_sa = NULL;
		node_buf_to_addr(&buf, &buf_sa);
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
					self_external = malloc(SZ_NODE_BF);
					memcpy(self_external, &buf, SZ_NODE_BF);
					sa_me_external = malloc(SZ_SOCKADDR);
					memcpy(sa_me_external, buf_sa, SZ_SOCKADDR);
					addr_to_str((struct sockaddr*)sa_me_external,
						me_external_ip,
						me_external_port,
						me_external_family);
					sprintf(sprintf, "Moi aussie %s port%s %s",
						me_external_ip,
						me_external_port,
						me_external_family);
					if (new_client_cb) new_client_cb(SERVER_SIGNIN, sprintf);
					stay_in_touch_with_server(SERVER_SIGNIN);
					init_chat_hp();
					break;
				}
				case STATUS_STAY_IN_TOUCH_RESPONSE: {
					if (stay_touch_recd_cb) stay_touch_recd_cb(SERVER_SIGNIN);
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
					node_min_t *new_peer_added;
					node_buf_to_node_min(&buf, &new_peer_added);
					add_node_min(peers, new_peer_added);
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
					punch_hole_in_peer(new_peer_added);
					break;
                    
				}
                    
				default: {
					if (unhandled_response_from_server)
						unhandled_response_from_server(buf.status);
					break;
				}
			}
		} else {
			node_min_t *existing_peer = find_node_min_from_sockaddr(peers, &sa_other);
			if (!existing_peer) {
				/* TODO: This is an issue. Either a security issue (how
				did an unknown peer get through the firewall) or my list
				of peers is wrong. */
				sprintf(sprintf, "FROM UNKNOWN peer: ip:%s port:%s fam:%s",
					other_ip,
					other_port,
					other_family);
				if (from_peer_cb) from_peer_cb(sprintf);
				continue;
			}

			char conf_stat[12];
			switch (existing_peer->status) {
				case STATUS_INIT_NODE:
				case STATUS_NEW_NODE:
				case STATUS_STAY_IN_TOUCH:
				case STATUS_STAY_IN_TOUCH_RESPONSE:
				case STATUS_CONFIRMED_NODE:
				case STATUS_NEW_PEER: {
					send_hole_punch(existing_peer);
					existing_peer->status = STATUS_CONFIRMED_PEER;
					strcpy(conf_stat, "UNCONFIRMED");
					break;
				}
				case STATUS_CONFIRMED_PEER:
				case STATUS_CHAT_PORT: {
					strcpy(conf_stat, "CONFIRMED");
					break;
				}
			}

			sprintf(sprintf, "from KNOWN AND %s peer: ip:%s port:%s fam:%s",
				conf_stat,
				other_ip,
				other_port,
				other_family);
			if (from_peer_cb) from_peer_cb(sprintf);
			// switch (buf.status) {
			// 	case STATUS_CHAT_PORT: {
			// 		sprintf(sprintf, "FROM Peer STATUS_CHAT_PORT %d", ntohs(buf.port));
			// 		if (from_peer_cb) from_peer_cb(sprintf);
			// 		break;
			// 	}
			// 	default: {
			// 		sprintf(sprintf, "FROM Peer status %d", buf.status);
			// 		if (from_peer_cb) from_peer_cb(sprintf);
			// 		break;
			// 	}
			// }
		}
		free(buf_sa);
	}

	return 0;
}

void init_chat_hp() {
	pthread_t chpt;
	int rc = pthread_create(&chpt, NULL, chat_hp_server, (void*)"chat_hp_server_thread");
	if (rc) {
		printf("ERROR in init_chat_hp; return code from pthread_create() is %d\n", rc);
		return;
	}
}

void *chat_hp_server(void *w) {
	printf("chat_hp_server %s\n", (char *)w);
	char sprintf[256];

	// Setup self
	// str_to_addr((struct sockaddr**)&sa_me_chat, NULL, "12001", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	// addr_to_str((struct sockaddr*)sa_me_chat, me_chat_ip, me_chat_port, me_chat_family);
	// sprintf(sprintf, "Chat moi %s port%s %s", me_chat_ip, me_chat_port, me_chat_family);
	// if (self_info_cb) self_info_cb(sprintf);
	struct sockaddr_in si_me;
	memset((char *) &si_me, 0, SZ_SOCKADDR_IN);
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(0);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_me_chat = (struct sockaddr*)&si_me;

	// Setup chat server
	str_to_addr(&sa_chat_server, "142.105.56.124", "9931", AF_INET, SOCK_DGRAM, 0);
	server_socklen = sa_chat_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	addr_to_str(sa_chat_server, server_internal_ip, server_internal_port, server_internal_family);
	sprintf(sprintf, "The chat server %s port%s %s %u",
		server_internal_ip,
		server_internal_port,
		server_internal_family,
		server_socklen);
	if (server_info_cb) server_info_cb(sprintf);

	// Setup sa_chat_other
	struct sockaddr sa_chat_other;
	char chat_other_ip[INET6_ADDRSTRLEN];
	char chat_other_port[20];
	char chat_other_family[20];
	socklen_t chat_other_socklen = DEFAULT_OTHER_ADDR_LEN;

	chat_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (chat_sock_fd == -1) {
		printf("There was a problem creating the socket\n");
	} else if (socket_created_cb) socket_created_cb(chat_sock_fd);

	int br = bind(chat_sock_fd, (struct sockaddr*)sa_me_chat, sizeof(*sa_me_chat));
	if ( br == -1 ) pfail("bind");
	if (socket_bound_cb) socket_bound_cb();

	chat_buf_t buf;
	memset(&buf, '\0', sizeof(buf));

	chat_server_socklen = sa_chat_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6
				: SZ_SOCKADDR_IN;
	size_t chat_sendto_len = sendto(chat_sock_fd, &buf, sizeof(node_t), 0, sa_chat_server, chat_server_socklen);
	if (chat_sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", chat_sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(chat_sendto_len);

	chat_server_conn_running = 1;
	while (chat_server_conn_running) {

		size_t recvf_len = recvfrom(chat_sock_fd, &buf, sizeof(buf), 0, &sa_chat_other, &chat_other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_chat_other, chat_other_ip, chat_other_port, chat_other_family);
		sprintf(sprintf, "%s port%s %s", chat_other_ip, chat_other_port, chat_other_family);
		if (recd_cb) recd_cb(recvf_len, chat_other_socklen, sprintf);
		chat_other_socklen = DEFAULT_OTHER_ADDR_LEN;

		switch (buf.status) {
			case CHAT_STATUS_NEW: {
				if (new_client_cb) new_client_cb(SERVER_CHAT, sprintf);
				stay_in_touch_with_server(SERVER_CHAT);
				break;
			}
			case CHAT_STATUS_STAY_IN_TOUCH_RESPONSE: {
				if (stay_touch_recd_cb) stay_touch_recd_cb(SERVER_CHAT);
				break;
			}
			default: printf("*&*&*&*&*&*&*&*&* chat server\n");
		}

	}

	pthread_exit("chat_hp_server exiting normally");
}
