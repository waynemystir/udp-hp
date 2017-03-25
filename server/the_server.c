#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include "hashtable.h"
#include "network_utils.h"
#include "crypto_wrapper.h"

#define RSA_PUB_KEY_FILEPATH "SUP_RSA_PUB_KEY"
#define RSA_PRI_KEY_FILEPATH "SUP_RSA_PRI_KEY"

char *rsa_public_key_str;
char *rsa_private_key_str;

pthread_t main_server_thread;
pthread_t authentication_server_thread;

int main_server_running = 1;
int authentication_server_running = 1;

int sock_fd;
int authn_sock_fd;

struct sockaddr si_other;
struct sockaddr sa_auth_other;
socklen_t slen = SZ_SOCKADDR;
hashtable_t hashtbl;

void pfail(char *s) {
	perror(s);
	exit(1);
}

int collect_rsa_keys() {
	rsa_public_key_str = read_file_to_str(RSA_PUB_KEY_FILEPATH);
	rsa_private_key_str = read_file_to_str(RSA_PRI_KEY_FILEPATH);
	if (!rsa_public_key_str || !rsa_private_key_str) {
		int ret = -1;
		generate_rsa_keypair(NULL, &rsa_private_key_str, &rsa_public_key_str,
			RSA_PRI_KEY_FILEPATH, RSA_PUB_KEY_FILEPATH);

		FILE *publ_file = fopen(RSA_PUB_KEY_FILEPATH, "r");
		FILE *priv_file = fopen(RSA_PRI_KEY_FILEPATH, "r");
		if (rsa_public_key_str && rsa_private_key_str && publ_file && priv_file) ret = 0;
		fclose(publ_file);
		fclose(priv_file);
		return ret;
	}
	return 0;
}

void load_hashtbl_from_db() {
	memset(&hashtbl, '\0', SZ_HASHTBL);
	add_user(&hashtbl, "waynemystir");
	add_user(&hashtbl, "julius_erving");
	add_user(&hashtbl, "mike_schmidt");
	add_user(&hashtbl, "pete_rose");

	add_contact_to_hashtbl(&hashtbl, "pete_rose", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "pete_rose", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "pete_rose", "pete_rose");
	add_contact_to_hashtbl(&hashtbl, "pete_rose", "julius_erving");

	add_contact_to_hashtbl(&hashtbl, "julius_erving", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "pete_rose");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "julius_erving");

	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "pete_rose");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "julius_erving");
	
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "pete_rose");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "julius_erving");
}

void notify_existing_peer_of_new_node(node_t *existing_peer, void *arg1, void *arg2, void *arg3) {
	if (!existing_peer || !arg1) return;
	node_t *new_node = arg1;
	char id_ep[MAX_CHARS_USERNAME];
	char id_nn[MAX_CHARS_USERNAME];
	strcpy(id_ep, arg2);
	strcpy(id_nn, arg3);

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

	node_buf_t *exip_node_buf, *new_node_buf;
	get_approp_node_bufs(existing_peer, new_node, &exip_node_buf, &new_node_buf, id_ep, id_nn);

	// And now we notify existing peer of new tail
	if (sendto(sock_fd, new_node_buf, SZ_NODE_BF, 0, &ep_addr, slen)==-1)
		pfail("sendto");

	// And notify new tail (i.e. si_other) of existing peer
	if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, &si_other, slen)==-1)
		pfail("sendto");

	free(exip_node_buf);
	free(new_node_buf);
}

void notify_existing_peer_of_new_chat_port(node_t *existing_peer, void *arg1, void *arg2, void *arg3) {
	node_t *peer_with_new_port = arg1;
	printf("notify_existing_peer_of_new_chat_port\n");
	if (nodes_equal(existing_peer, peer_with_new_port)) return;
	char id_ep[MAX_CHARS_USERNAME];
	char id_nn[MAX_CHARS_USERNAME];
	strcpy(id_ep, arg2);
	strcpy(id_nn, arg3);

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

	node_buf_t *exip_node_buf, *pwnp_buf;
	get_approp_node_bufs(existing_peer, peer_with_new_port, &exip_node_buf, &pwnp_buf, id_ep, id_nn);
	exip_node_buf->status = STATUS_PROCEED_CHAT_HP;
	pwnp_buf->status = STATUS_PROCEED_CHAT_HP;

	// And now we notify existing peer of new tail
	if (sendto(sock_fd, pwnp_buf, SZ_NODE_BF, 0, &ep_addr, slen)==-1)
		pfail("sendto");

	// And notify peer_with_new_port (i.e. si_other) of existing peer
	if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, &si_other, slen)==-1)
		pfail("sendto");

	free(exip_node_buf);
	free(pwnp_buf);
}

void notify_contact_of_new_node(contact_t *contact, void *arg1, void *arg2, void *arg3) {
	if (!contact || !contact->hn) return;
	// And notify peer_with_new_port (i.e. si_other) of existing peer
	node_buf_t contact_nb;
	contact_nb.status = STATUS_NOTIFY_EXISTING_CONTACT;
	strcpy(contact_nb.id, contact->hn->username);
	if (sendto(sock_fd, &contact_nb, SZ_NODE_BF, 0, &si_other, slen)==-1)
		pfail("sendto");

	if (!arg1 || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, notify_existing_peer_of_new_node, arg1, contact->hn->username, arg2);
}

void notify_contact_of_new_chat_port(contact_t *contact, void *arg1, void *arg2, void *arg3) {
	printf("notify_contact_of_new_chat_port\n");
	if (!arg1 || !contact || !contact->hn || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, notify_existing_peer_of_new_chat_port, arg1, contact->hn->username, arg2);
}

void *authentication_server_endpoint(void *arg) {
	printf("authentication_server_endpoint thread started\n");
	for (int j = 0; j < 10;) printf("authN %d\n", ++j);

	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	auth_buf_t buf;

	authn_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( authn_sock_fd == -1 ) pfail("socket");
	printf("authentication_server_endpoint 1 %d\n", authn_sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	char auth_port[10];
	sprintf(auth_port, "%d", AUTHENTICATION_PORT);
	str_to_addr((struct sockaddr**)&si_me, NULL, auth_port, AF_INET, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	printf("authentication_server_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(authn_sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("bind");
	printf("authentication_server_endpoint 3 %d\n", br);

	while (authentication_server_running) {
		// printf("main -: 3\n");
		recvf_len = recvfrom(authn_sock_fd, &buf, SZ_AU_BF, 0, &sa_auth_other, &slen);
		if ( recvf_len == -1) pfail("recvfrom");

		char ip_str[INET6_ADDRSTRLEN];
		unsigned short port;
		unsigned short family;
		// void *addr = &(sa_auth_other.sin_addr);
		// inet_ntop( AF_INET, &(sa_auth_other.sin_addr), ip_str, sizeof(ip_str) );
		addr_to_str_short( &sa_auth_other, ip_str, &port, &family );
		printf("Auth received packet (%zu bytes) from %s port%d %d\n", recvf_len, ip_str, port, family);

		switch (buf.status) {
			case AUTH_STATUS_RSA_SWAP: {
				printf("The node's RSA pub key (%s)\n", buf.rsa_pub_key);
				memset(buf.rsa_pub_key, '\0', RSA_PUBLIC_KEY_LEN);
				memcpy(buf.rsa_pub_key, rsa_public_key_str, RSA_PUBLIC_KEY_LEN);
				sendto_len = sendto(authn_sock_fd, &buf, SZ_AU_BF, 0, &sa_auth_other, slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				break;
			}
			case AUTH_STATUS_AES_SWAP: {
				break;
			}
			case AUTH_STATUS_NEW_USER: {
				break;
			}
			case AUTH_STATUS_AUTH_TOKEN: {
				break;
			}
			case AUTH_STATUS_RE_AUTH: {
				break;
			}
			default: {
				break;
			}
		}
	}

	pthread_exit("authentication_server_thread exited normally");
}

void *main_server_endpoint(void *arg) {
	printf("main_server_endpoint 0 %s %zu %zu %zu %zu\n", (char *)arg,
		SZ_NODE, sizeof(node_t),
		SZ_NODE_BF, sizeof(node_buf_t));

	size_t recvf_len, sendto_len;
	struct sockaddr_in *si_me;
	node_buf_t buf;
	// nodes = malloc(SZ_LINK_LIST);
	// memset(nodes, '\0', SZ_LINK_LIST);

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( sock_fd == -1 ) pfail("socket");
	printf("main_server_endpoint 1 %d\n", sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	str_to_addr((struct sockaddr**)&si_me, NULL, "9930", AF_INET, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	printf("main_server_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("bind");
	printf("main_server_endpoint 3 %d\n", br);

	while (main_server_running) {
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
				printf("New node %s %s %d\n", buf.id, ip_str, port);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				// TODO We must add a check here to see if this new node
				// already exists in our linked list. If so, how to 
				// handle that?
				node_t *new_tail;
				// TODO Add a get_new_head
				// If the user just signed in from this device
				// It will probably get the most use
				get_new_tail(hn->nodes, &new_tail);
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
				node_external_to_node_buf(new_tail, &new_tail_buf, hn->username);
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
				contacts_perform(hn->contacts, notify_contact_of_new_node, new_tail, hn->username, NULL);
				// TODO notify new_node of itself i.e. the other nodes in hn->nodes
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
			case STATUS_ACQUIRED_CHAT_PORT: {
				printf("STATUS_ACQUIRED_CHAT_PORT from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					printf("STATUS_ACQUIRED_CHAT_PORT no hn for user (%s)\n", buf.id);
					break;
				}

				node_t *peer_with_new_chat_port = find_node_from_sockaddr(hn->nodes,
					&si_other,
					SERVER_SIGNIN);
				if (peer_with_new_chat_port) {
					peer_with_new_chat_port->external_chat_port = buf.chat_port;
					// TODO how to handle internal_chat_port here?
					// Just use buf.int_or_ext?
					contacts_perform(hn->contacts,
						notify_contact_of_new_chat_port,
						peer_with_new_chat_port, hn->username, NULL);
				}
				break;
			}
			default: {
				char *buf_char = (char *) &buf;
				printf("None of the above - buf.status -: %d -: %s\n", buf.status, buf_char);
				break;
			}
		}

		// printf("Now we have %d nodes\n", nodes->node_count);
		// And we go back to listening. Notice that since UDP has no notion
        	// of connections, we can use the same socket to listen for data
        	// from different clients.
	}

	close(sock_fd);
	freehashtable(&hashtbl);

	pthread_exit("main_server_thread exited normally");
}

int main() {
	printf("the_server main 0 %zu %zu\n", sizeof(STATUS_TYPE), sizeof(struct node));

	// Get the keys
	int ckr = collect_rsa_keys();
	if (ckr == -1) {
		printf("ERROR collecting RSA keys\n");
		exit(-1);
	}

	// Load up the hashtbl
	load_hashtbl_from_db();

	// Fire up the authentication server
	char *authn_exit_msg;
	int atcr = pthread_create(&authentication_server_thread, NULL,
		authentication_server_endpoint, (void *)"authN_server_thread");
	if (atcr) {
		printf("ERROR starting authentication_server_thread: %d\n", atcr);
		exit(-1);
	}

	char *thread_exit_msg;
	int pcr = pthread_create(&main_server_thread, NULL, main_server_endpoint, (void *)"main_server_thread");
	if (pcr) {
		printf("ERROR starting main_server_thread: %d\n", pcr);
		exit(-1);
	}

	pthread_join(authentication_server_thread, (void**)&authn_exit_msg);
	pthread_join(main_server_thread,(void**)&thread_exit_msg);

	printf("Wrapping up sign_in_service: %s\n", thread_exit_msg);
	return 0;
}