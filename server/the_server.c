#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "hashtable.h"
#include "network_utils.h"
#include "crypto_wrapper.h"

#define RSA_PUB_KEY_FILEPATH "SUP_RSA_PUB_KEY"
#define RSA_PRI_KEY_FILEPATH "SUP_RSA_PRI_KEY"
#define AES_KEY_FILEPATH "SUP_AES_KEY"
#define AES_IV_FILEPATH "SUP_AES_IV"
#define SERVER_LOG_FILE_NAME "SERVER_LOG_FILE_NAME"

char environment_str[64];
char *server_ip_str;

char *rsa_public_key_str;
char *rsa_private_key_str;
unsigned char *aes_key;
unsigned char *aes_iv;

pthread_t main_server_thread;
pthread_t authentication_server_thread;
pthread_t chat_thread;
pthread_t search_server_thread;

int main_server_running = 1;
int authentication_server_running = 1;
int search_server_running = 1;
int chat_running = 1;

int sock_fd;
int authn_sock_fd;
int search_sock_fd;
int chat_sock_fd;

hashtable_t hashtbl;
authn_hashtable_t authn_tbl;
token_hashtable_t token_tbl;

void pfail(char *s) {
	printf("pfail-0\n");
	wlog("PPPPPPPPPPFFFFFFFFAAAAAAAAAIIIIIIIIILLLLLLLL (%s)\n", s);
	perror(s);
	char *w2 = strerror(errno);
	char w3[512];
	sprintf(w3, "(%s) (%s)\n", s, w2);
	wlog("%s", w3);
	// exit(1);
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

void create_aes_iv() {
	unsigned char iv[NUM_BYTES_AES_IV];
	memset(iv, '\0', NUM_BYTES_AES_IV);
	if (!RAND_bytes(iv, sizeof(iv))) {
		wlog("RAND_bytes failed for iv\n");
		ERR_print_errors_fp(stdout);
		return;
	}

	free(aes_iv);
	aes_iv = malloc(NUM_BYTES_AES_IV);
	memset(aes_iv, '\0', NUM_BYTES_AES_IV);
	memcpy(aes_iv, iv, NUM_BYTES_AES_IV);
}

void create_aes_key() {
	create_aes_iv();
	if (aes_key) return;

	unsigned char symmetric_key[NUM_BYTES_AES_KEY];
	memset(symmetric_key, '\0', NUM_BYTES_AES_KEY);

	if (!RAND_bytes(symmetric_key, sizeof(symmetric_key))) {
		wlog("RAND_bytes failed for symmetric_key\n");
		ERR_print_errors_fp(stdout);
	}

	aes_key = malloc(NUM_BYTES_AES_KEY);
	memset(aes_key, '\0', NUM_BYTES_AES_KEY);
	memcpy(aes_key, symmetric_key, NUM_BYTES_AES_KEY);
}

int collect_aes_key_and_iv() {
	aes_key = read_file_to_bytes(AES_KEY_FILEPATH);
	aes_iv = read_file_to_bytes(AES_IV_FILEPATH);
	if (!aes_key) {
		create_aes_key();
		if (!aes_key) return -1;
	}
	FILE *aes_key_file = fopen(AES_KEY_FILEPATH, "wb+");
	if (aes_key_file) {
		fwrite(aes_key, 1, NUM_BYTES_AES_KEY, aes_key_file);
		fclose(aes_key_file);
	}

	if (!aes_iv) {
		create_aes_iv();
		if (!aes_iv) return -1;
	}
	FILE *aes_iv_file = fopen(AES_IV_FILEPATH, "wb+");
	if (aes_iv_file) {
		fwrite(aes_iv, 1, NUM_BYTES_AES_IV, aes_iv_file);
		fclose(aes_iv_file);
	}

	return 0;
}

void load_hashtbl_from_db() {
	memset(&hashtbl, '\0', SZ_HASHTBL);
	add_user(&hashtbl, "waynemystir", "wes");
	add_user(&hashtbl, "julius_erving", "je");
	add_user(&hashtbl, "mike_schmidt", "ms");
	add_user(&hashtbl, "alan_turing", "at");
	add_user(&hashtbl, "w", "w");
	add_user(&hashtbl, "apple_review", "password_apple");

	add_contact_to_hashtbl(&hashtbl, "apple_review", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "apple_review", "alan_turing");

	add_contact_to_hashtbl(&hashtbl, "alan_turing", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "alan_turing", "apple_review");
	add_contact_to_hashtbl(&hashtbl, "alan_turing", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "alan_turing", "alan_turing");
	add_contact_to_hashtbl(&hashtbl, "alan_turing", "julius_erving");

	add_contact_to_hashtbl(&hashtbl, "julius_erving", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "alan_turing");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "julius_erving", "julius_erving");

	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "alan_turing");
	add_contact_to_hashtbl(&hashtbl, "mike_schmidt", "julius_erving");
	
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "waynemystir");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "apple_review");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "mike_schmidt");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "alan_turing");
	add_contact_to_hashtbl(&hashtbl, "waynemystir", "julius_erving");

	add_user(&hashtbl, "abigail", "ab");
	add_user(&hashtbl, "barbara", "ba");
	add_user(&hashtbl, "charlie", "ch");
	add_user(&hashtbl, "david", "da");
	add_user(&hashtbl, "edward", "ed");
	add_user(&hashtbl, "frank", "fr");
	add_user(&hashtbl, "gretchen", "gr");
	add_user(&hashtbl, "henry", "he");
	add_user(&hashtbl, "isabel", "is");
	add_user(&hashtbl, "jonathan", "jo");
	add_user(&hashtbl, "keith", "ke");
	add_user(&hashtbl, "laura", "la");
	add_user(&hashtbl, "michael", "mi");
	add_user(&hashtbl, "nathan", "na");
	add_user(&hashtbl, "oliver", "ol");
	add_user(&hashtbl, "peter", "pe");
	add_user(&hashtbl, "pauline", "pa");
	add_user(&hashtbl, "rachel", "ra");
	add_user(&hashtbl, "sharon", "sh");
	add_user(&hashtbl, "thomas", "th");
	add_user(&hashtbl, "ulysese", "ul");
	add_user(&hashtbl, "vincent", "vi");
	add_user(&hashtbl, "walter", "wa");
	add_user(&hashtbl, "william", "wi");
	add_user(&hashtbl, "amy", "am");
	add_user(&hashtbl, "bernard", "be");
	add_user(&hashtbl, "dorothy", "do");
}

void notify_existing_peer_of_new_node(node_t *existing_peer,
	void *arg1, // the new node
	void *arg2, // the username of the existing node/peer
	void *arg3, // the username of the new node
	void *arg4) // the sockaddr of the new node
{
	wlog("notify_existing_peer_of_new_node 111 ep-id(%s)(%lu) nn-id(%s)(%lu)\n",
		(char*)arg2, strlen((char*)arg2), (char*)arg3, strlen((char*)arg3));
	if (!existing_peer || !arg1) return;
	node_t *new_node = arg1;
	char id_ep[MAX_CHARS_USERNAME+200];
	char id_nn[MAX_CHARS_USERNAME+200];
	memset(id_ep, '\0', MAX_CHARS_USERNAME+200);
	memset(id_nn, '\0', MAX_CHARS_USERNAME+200);
	// memcpy((char*)id_ep, (char*)arg2, MAX_CHARS_USERNAME);
	// memcpy((char*)id_nn, (char*)arg3, MAX_CHARS_USERNAME);
	strcpy((char*)id_ep, (char*)arg2);
	strcpy((char*)id_nn, (char*)arg3);

	// Let's get the sockaddr of existing_peer
	struct sockaddr ep_addr;
	switch (existing_peer->external_family) {
		case SUP_AF_INET_4: {
			ep_addr.sa_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_port = existing_peer->external_port;
			((struct sockaddr_in*)&ep_addr)->sin_addr.s_addr = existing_peer->external_ip4;
			break;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			ep_addr.sa_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_port = existing_peer->external_port;
			memcpy(((struct sockaddr_in6*)&ep_addr)->sin6_addr.s6_addr, existing_peer->external_ip6, 16);
			break;
		}
		default: return;
	}

	wlog("notify_existing_peer_of_new_node 22222ggggggg22222 id_ep(%s) id_nn(%s)\n", id_ep, id_nn);
	wlog("notify_existing_peer_of_new_node 333 ep-id(%s) nn-id(%s)\n", (char*)arg2, (char*)arg3);
	node_buf_t *exip_node_buf, *new_node_buf;
	get_approp_node_bufs(existing_peer, new_node, &exip_node_buf, &new_node_buf, (char*)arg2, id_nn);
	exip_node_buf->status = STATUS_NEW_PEER;
	new_node_buf->status = STATUS_NEW_PEER;

	// And now we notify existing peer of new tail
	wlog("notify_existing_peer_of_new_node nn-id(%s)(%d)\n", new_node_buf->id, ntohs(new_node_buf->port));
	socklen_t ep_socklength = ep_addr.sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, new_node_buf, SZ_NODE_BF, 0, &ep_addr, ep_socklength)==-1)
		pfail("sendto");

	// And notify new tail (i.e. si_other) of existing peer
	wlog("notify_existing_peer_of_new_node ep-id(%s)(%d)\n", exip_node_buf->id, ntohs(exip_node_buf->port));
	socklen_t nn_socklength = ((struct sockaddr*)arg4)->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, (struct sockaddr*)arg4, nn_socklength)==-1)
		pfail("sendto");

	free(exip_node_buf);
	free(new_node_buf);
}

void notify_existing_peer_of_deinit_node(node_t *existing_peer,
	void *arg1, // the deinit node
	void *arg2, // the username of the existing node/peer
	void *arg3, // the username of the deinit node
	void *arg4) // the sockaddr of the deinit node
{
	if (!existing_peer || !arg1 || !arg2 || !arg3 || !arg4) return;
	node_t *deinit_node = arg1;
	char id_ep[MAX_CHARS_USERNAME];
	char id_nn[MAX_CHARS_USERNAME];
	strcpy(id_ep, arg2);
	strcpy(id_nn, arg3);

	// Let's get the sockaddr of existing_peer
	struct sockaddr ep_addr;
	switch (existing_peer->external_family) {
		case SUP_AF_INET_4: {
			ep_addr.sa_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_port = existing_peer->external_port;
			((struct sockaddr_in*)&ep_addr)->sin_addr.s_addr = existing_peer->external_ip4;
			break;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			ep_addr.sa_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_port = existing_peer->external_port;
			memcpy(((struct sockaddr_in6*)&ep_addr)->sin6_addr.s6_addr, existing_peer->external_ip6, 16);
			break;
		}
		default: return;
	}

	node_buf_t *exip_node_buf, *deinit_node_buf;
	get_approp_node_bufs(existing_peer, deinit_node, &exip_node_buf, &deinit_node_buf, id_ep, id_nn);
	exip_node_buf->status = STATUS_DEINIT_NODE;
	deinit_node_buf->status = STATUS_DEINIT_NODE;

	// And now we notify existing peer of new tail
	socklen_t ep_socklength = ep_addr.sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, deinit_node_buf, SZ_NODE_BF, 0, &ep_addr, ep_socklength)==-1)
		pfail("sendto");

	// And notify new tail (i.e. si_other) of existing peer
	// if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, (struct sockaddr*)arg4, main_slen)==-1)
	// 	pfail("sendto");

	free(exip_node_buf);
	free(deinit_node_buf);

}

void notify_existing_peer_of_new_chat_port(node_t *existing_peer,
	void *arg1, // node/peer with the new chat port
	void *arg2, // the username of the existing node/peer
	void *arg3, // the username of the node with new port
	void *arg4) // the sockaddr of the node with new port
{
	node_t *peer_with_new_port = arg1;
	wlog("notify_existing_peer_of_new_chat_port\n");
	// TODO double check this isn't broken after changing nodes_equal implementation for int_or_ext
	if (nodes_equal(existing_peer, peer_with_new_port)) return;
	char id_ep[MAX_CHARS_USERNAME];
	char id_nn[MAX_CHARS_USERNAME];
	strcpy(id_ep, arg2);
	strcpy(id_nn, arg3);

	// Let's get the sockaddr of existing_peer
	struct sockaddr ep_addr;
	switch (existing_peer->external_family) {
		case SUP_AF_INET_4: {
			ep_addr.sa_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_family = AF_INET;
			((struct sockaddr_in*)&ep_addr)->sin_port = existing_peer->external_port;
			((struct sockaddr_in*)&ep_addr)->sin_addr.s_addr = existing_peer->external_ip4;
			break;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			ep_addr.sa_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)&ep_addr)->sin6_port = existing_peer->external_port;
			memcpy(((struct sockaddr_in6*)&ep_addr)->sin6_addr.s6_addr, existing_peer->external_ip6, 16);
			break;
		}
		default: return;
	}

	node_buf_t *exip_node_buf, *pwnp_buf;
	get_approp_node_bufs(existing_peer, peer_with_new_port, &exip_node_buf, &pwnp_buf, (char*)arg2, id_nn);
	exip_node_buf->status = STATUS_PROCEED_CHAT_HP;
	pwnp_buf->status = STATUS_PROCEED_CHAT_HP;
	wlog("BBBBBBB (%s)(%s))\n", pwnp_buf->id, exip_node_buf->id);
	wlog("&*&*&*&*&*&*&*&&*&*&*&*&*&*&*&&*&*&*&*&*&*&*& (%s)(%d)(%s)(%d)\n",
		pwnp_buf->id, ntohs(pwnp_buf->chat_port), exip_node_buf->id, ntohs(exip_node_buf->chat_port));

	// And now we notify existing peer of new tail
	socklen_t ep_socklength = ep_addr.sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, pwnp_buf, SZ_NODE_BF, 0, &ep_addr, ep_socklength)==-1)
		pfail("sendto");

	// And notify peer_with_new_port (i.e. si_other) of existing peer
	socklen_t nn_socklength = ((struct sockaddr*)arg4)->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, exip_node_buf, SZ_NODE_BF, 0, (struct sockaddr*)arg4, nn_socklength)==-1)
		pfail("sendto");

	free(exip_node_buf);
	free(pwnp_buf);
}

void notify_contact_of_new_node(contact_t *contact,
	void *arg1, // the new node
	void *arg2, // the username of the new node
	void *arg3) // the sockaddr of the new node
{
	wlog("notify_contact_of_new_node\n");
	if (!contact || !contact->hn) return;
	// And notify peer_with_new_port (i.e. si_other) of existing peer
	node_buf_t contact_nb;
	contact_nb.status = STATUS_NOTIFY_EXISTING_CONTACT;
	strcpy(contact_nb.id, contact->hn->username);
	wlog("notify_contact_of_new_node (%s)(%s)\n", contact->hn->username, contact_nb.id);
	socklen_t nn_socklength = ((struct sockaddr*)arg3)->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	if (sendto(sock_fd, &contact_nb, SZ_NODE_BF, 0, (struct sockaddr*)arg3, nn_socklength)==-1)
		pfail("sendto");

	if (!arg1 || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, notify_existing_peer_of_new_node, arg1, contact->hn->username, arg2, arg3);
}

void notify_contact_of_deinit_node(contact_t *contact,
	void *arg1, // the deinit node
	void *arg2, // the username of the deinit node
	void *arg3) // the sockaddr of the deinit node
{
	wlog("notify_contact_of_deinit_node\n");
	if (!arg1 || !arg2 || !arg3 || !contact || !contact->hn || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, notify_existing_peer_of_deinit_node, arg1, contact->hn->username, arg2, arg3);
}

void notify_contact_of_new_chat_port(contact_t *contact, void *arg1, void *arg2, void *arg3) {
	wlog("notify_contact_of_new_chat_port\n");
	if (!arg1 || !contact || !contact->hn || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, notify_existing_peer_of_new_chat_port, arg1, contact->hn->username, arg2, arg3);
}

void *authentication_server_endpoint(void *arg) {
	wlog("authentication_server_endpoint thread started (%d)(%d)(%d)(%d)\n",
		NUM_BITS_AES_KEY, NUM_BYTES_AES_KEY, NUM_BITS_IV_KEY, NUM_BYTES_AES_IV);

	size_t recvf_len, sendto_len;
	struct sockaddr_in6 *si_me;
	authn_buf_t buf;
	struct sockaddr_in6 sa_auth_other;
	socklen_t authn_slen = SZ_SOCKADDR_IN6;

	authn_sock_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if ( authn_sock_fd == -1 ) pfail("socket");
	wlog("authentication_server_endpoint 1 %d\n", authn_sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	char authn_port[10];
	get_authentication_port_as_str(authn_port);
	str_to_addr((struct sockaddr**)&si_me, NULL, authn_port, AF_INET6, SOCK_STREAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	wlog("authentication_server_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(authn_sock_fd, (struct sockaddr*)si_me, SZ_SOCKADDR_IN6);
	if ( br == -1 ) pfail("authn bind");
	wlog("authentication_server_endpoint 3 %d\n", br);

	int lr = listen(authn_sock_fd, MAX_CONNECTIONS);
	if ( lr < 0 ) pfail("authn listen");
	wlog("authentication_server_endpoint 4: started listening\n");

	memset(&authn_tbl, '\0', SZ_AUN_TBL);

	while (authentication_server_running) {
		wlog("AUTHNNNNNNNNNNNNNNNN 1111111\n");
		int connecting_sock_fd = accept(authn_sock_fd, (struct sockaddr*)&sa_auth_other, &authn_slen);
		wlog("AUTHNNNNNNNNNNNNNNNN 2222222\n");

		if ( connecting_sock_fd < 0 ) pfail("authn accept");
		wlog("authentication_server_endpoint 5: we've got a connection.\n");

		while ((recvf_len = recv(connecting_sock_fd, &buf, SZ_AE_BUF, 0)) > 0) {
			wlog("AUTHNNNNNNNNNNNNNNNN 3333333\n");

			char ip_str[INET6_ADDRSTRLEN];
			unsigned short port;
			unsigned short family;
			// void *addr = &(sa_auth_other.sin_addr);
			// inet_ntop( AF_INET, &(sa_auth_other.sin_addr), ip_str, sizeof(ip_str) );
			addr_to_str_short((struct sockaddr*)&sa_auth_other, ip_str, &port, &family);
			wlog("AUTH received packet (%d):(%s) (%zu bytes) from %s port%d %d\n", buf.status,
				authn_status_to_str(buf.status), recvf_len, ip_str, port, family);

// start_switch:
			switch (buf.status) {
				case AUTHN_STATUS_ENCRYPTED: {
					wlog("AUTHN_STATUS_ENCRYPTED started\n");
					char *key = authn_addr_info_to_key(family, ip_str, port);
					wlog("AUTHN_STATUS_ENCRYPTED The node's key (%s)\n", key);
					authn_node_t *an = lookup_authn_node(&authn_tbl, key);
					if (!an) {
						wlog("AUTHN_STATUS_ENCRYPTED No node was found for key (%s)\n", key);
						break;
					}
					wlog("And the node was found with key (%s)\n", an->key);
					wlog("I have temporarily disabled encryption, so how can AUTHN_STATUS_ENCRYPTED possibly be called????\n");
					break;

					// authn_buf_encrypted_t *be = (authn_buf_encrypted_t*)&buf;

					// unsigned char decrypted_buf[SZ_AUN_BF + AES_PADDING];
					// memset(decrypted_buf, '\0', SZ_AUN_BF + AES_PADDING);
					// wlog("Lets AES descrypt with (%s)(%s)(%s)\n", be ? "GOD" : "BAD",
					// 	an->aes_key ? "GOD" : "BAD", an->aes_iv ? "GOD" : "BAD");
					// int dl = aes_decrypt(be->encrypted_buf, be->encrypted_len, an->aes_key, an->aes_iv, decrypted_buf);
					// wlog("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
					// memset(&buf, '\0', sizeof(buf));
					// memcpy(&buf, decrypted_buf, dl);
					// wlog("aes_decrypt copied (%s)\n", buf.id);
					// goto start_switch;
				}
				case AUTHN_STATUS_RSA_SWAP: {
					char *key = authn_addr_info_to_key(family, ip_str, port);
					wlog("The node's key (%s)\n", key);
					authn_node_t *new_authn_node = add_authn_node(&authn_tbl, AUTHN_STATUS_RSA_SWAP_RESPONSE, key);
					wlog("And the node was added with key (%s)\n", new_authn_node->key);
					memset(new_authn_node->rsa_pub_key, '\0', RSA_PUBLIC_KEY_LEN);
					memcpy(new_authn_node->rsa_pub_key, buf.rsa_pub_key, strlen((char*)buf.rsa_pub_key));
					// wlog("The node's RSA pub key (%s)\n", new_authn_node->rsa_pub_key);

					memset(&buf, '\0', SZ_AUN_BF);
					buf.status = AUTHN_STATUS_RSA_SWAP_RESPONSE;
					memset(buf.rsa_pub_key, '\0', RSA_PUBLIC_KEY_LEN);
					memcpy(buf.rsa_pub_key, rsa_public_key_str, RSA_PUBLIC_KEY_LEN);
					// wlog("Sending RSA public key (%s) to node\n", buf.rsa_pub_key);

					sendto_len = sendto(connecting_sock_fd, &buf, SZ_AUN_BF, 0, (struct sockaddr*)&sa_auth_other, authn_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}
					wlog("AUTHN_STATUS_RSA_SWAP BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB (%s)\n", key);
					break;
				}
				case AUTHN_STATUS_AES_SWAP: {
					char *key = authn_addr_info_to_key(family, ip_str, port);
					wlog("The node's key (%s)\n", key);
					authn_node_t *an = lookup_authn_node(&authn_tbl, key);
					if (!an) {
						wlog("No node was found for key (%s)\n", key);
						break;
					}
					wlog("And the node was found with key (%s)\n", an->key);

					RSA *rsa_priv_key;
					unsigned char rsa_decrypted_aes_key[256];
					memset(rsa_decrypted_aes_key, '\0', 256);
					int result_len = 0;
					load_private_key_from_str(&rsa_priv_key, rsa_private_key_str);
					// wlog("Lets rsa decrypt with (%lu)(%lu)(%s)\n", sizeof(buf.aes_key),
					// 	sizeof(rsa_decrypted_aes_key), rsa_private_key_str);
					rsa_decrypt(rsa_priv_key, buf.aes_key, rsa_decrypted_aes_key, &result_len);
					// wlog("rsa_decrypted:(%s)(%d)\n", rsa_decrypted_aes_key, result_len);

					memset(an->aes_key, '\0', NUM_BYTES_AES_KEY);
					memcpy(an->aes_key, rsa_decrypted_aes_key, result_len);
					// I guess the initialization vector doesn't need to be encrypted
					// http://stackoverflow.com/questions/8804574/aes-encryption-how-to-transport-iv
					memset(an->aes_iv, '\0', NUM_BYTES_AES_IV);
					memcpy(an->aes_iv, buf.aes_iv, NUM_BYTES_AES_IV);
					// wlog("The node's AES key (%s)\n", an->aes_key);
					// wlog("The node's AES iv (%s)\n", an->aes_iv);
					wlog("AUTHN_STATUS_AES_SWAP GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG (%s)\n", key);

					memset(&buf, '\0', SZ_AUN_BF);
					buf.status = AUTHN_STATUS_AES_SWAP_RESPONSE;
					// There is no need to send the server's AES key
					// to the node... in fact, we may not need a server
					// AES key at all
					// memset(buf.aes_key, '\0', NUM_BYTES_AES_KEY);
					// memcpy(buf.aes_key, aes_key, NUM_BYTES_AES_KEY);
					// memset(buf.aes_iv, '\0', NUM_BYTES_AES_IV);
					// memcpy(buf.aes_iv, aes_iv, NUM_BYTES_AES_IV);
					sendto_len = sendto(connecting_sock_fd, &buf, SZ_AUN_BF, 0, (struct sockaddr*)&sa_auth_other, authn_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}
					wlog("AUTHN_STATUS_AES_SWAP HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH (%s)\n", key);
					break;
				}
				case AUTHN_STATUS_NEW_USER: {
					char *key = authn_addr_info_to_key(family, ip_str, port);
					wlog("AUTHN_STATUS_NEW_USER The node's key (%s)\n", key);
					authn_node_t *an = lookup_authn_node(&authn_tbl, key);
					if (!an) {
						wlog("AUTHN_STATUS_NEW_USER No node was found for key (%s)\n", key);
						break;
					}
					wlog("AUTHN_STATUS_NEW_USER And the node was found with key (%s)\n", an->key);

					AUTHN_CREDS_CHECK_RESULT cr = -1;
					hash_node_t *hn = lookup_user(&hashtbl, buf.id);
					if (hn) cr = AUTHN_CREDS_CHECK_RESULT_USERNAME_ALREADY_EXISTS;
					else cr = AUTHN_CREDS_CHECK_RESULT_GOOD;

					add_user(&hashtbl, buf.id, buf.pw);
					wlog("New user added (%s)(%s)\n", buf.id, buf.pw);

					memset(&buf, '\0', sizeof(buf));
					buf.status = AUTHN_STATUS_CREDS_CHECK_RESULT;
					buf.authn_result = cr;

					if (cr == AUTHN_CREDS_CHECK_RESULT_GOOD) {
						unsigned char authentication_token[AUTHEN_TOKEN_LEN];
						memset(authentication_token, '\0', AUTHEN_TOKEN_LEN);
						if (!RAND_bytes(authentication_token, sizeof(authentication_token))) {
							wlog("RAND_bytes failed for authentication_token\n");
							ERR_print_errors_fp(stdout);
							break;
						}
						memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
						add_token_node(&token_tbl, authentication_token);
						remove_authn_node(&authn_tbl, key);
					}

					sendto_len = sendto(connecting_sock_fd, &buf, SZ_AUN_BF, 0, (struct sockaddr*)&sa_auth_other, authn_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}
					break;
				}
				case AUTHN_STATUS_EXISTING_USER: {
					wlog("AUTHN_STATUS_EXISTING_USER username (%s)(%s)\n", buf.id, buf.pw);
					char *key = authn_addr_info_to_key(family, ip_str, port);
					authn_node_t *an = lookup_authn_node(&authn_tbl, key);
					if (!an) {
						wlog("AUTHN_STATUS_EXISTING_USER: No node was found for key (%s)\n", key);
						break;
					}

					AUTHN_CREDS_CHECK_RESULT cr = -1;
					hash_node_t *hn = lookup_user(&hashtbl, buf.id);
					if (!hn) cr = AUTHN_CREDS_CHECK_RESULT_USER_NOT_FOUND;
					else if (strcmp(hn->password, buf.pw) != 0) cr = AUTHN_CREDS_CHECK_RESULT_WRONG_PASSWORD;
					else cr = AUTHN_CREDS_CHECK_RESULT_GOOD;

					wlog("AUTHN_STATUS_EXISTING_USER (%s)(%s)(%s)\n", creds_check_result_to_str(cr), buf.id, buf.pw);

					memset(&buf, '\0', sizeof(buf));
					buf.status = AUTHN_STATUS_CREDS_CHECK_RESULT;
					buf.authn_result = cr;

					if (cr == AUTHN_CREDS_CHECK_RESULT_GOOD) {
						unsigned char authentication_token[AUTHEN_TOKEN_LEN];
						memset(authentication_token, '\0', AUTHEN_TOKEN_LEN);

						wlog("AUTHN_STATUS_EXISTING_USER about to RAND_bytes (%s)(%s)(%s)\n",
							creds_check_result_to_str(cr), buf.id, buf.pw);

						if (!RAND_bytes(authentication_token, sizeof(authentication_token))) {
							wlog("RAND_bytes failed for authentication_token\n");
							ERR_print_errors_fp(stdout);
							break;
						}

						wlog("AUTHN_STATUS_EXISTING_USER RAND_bytes done (%s)(%s)(%s)\n",
							creds_check_result_to_str(cr), buf.id, buf.pw);

						memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);

						wlog("AUTHN_STATUS_EXISTING_USER memcpy authn_token done (%s)(%s)(%s)\n",
							creds_check_result_to_str(cr), buf.id, buf.pw);

						add_token_node(&token_tbl, authentication_token);
						remove_authn_node(&authn_tbl, key);

						wlog("AUTHN_STATUS_EXISTING_USER done adding token node (%s)(%s)(%s)\n",
							creds_check_result_to_str(cr), buf.id, buf.pw);
					}

					wlog("AUTHN_STATUS_EXISTING_USER about to sendto (%s)(%s)(%s)\n",
						creds_check_result_to_str(cr), buf.id, buf.pw);

					sendto_len = sendto(connecting_sock_fd, &buf, SZ_AUN_BF, 0, (struct sockaddr*)&sa_auth_other, authn_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}

					wlog("AUTHN_STATUS_EXISTING_USER sendto DONE (%s)(%s)(%s)\n",
						creds_check_result_to_str(cr), buf.id, buf.pw);

					// TODO if cr == AUTHN_CREDS_CHECK_RESULT_GOOD, remove record from authn_tbl?
					break;
				}
				case AUTHN_STATUS_SIGN_OUT: {
					// TODO
					break;
				}
				case AUTHN_STATUS_RSA_SWAP_RESPONSE:
				case AUTHN_STATUS_AES_SWAP_RESPONSE:
				case AUTHN_STATUS_NEW_USER_RESPONSE:
				case AUTHN_STATUS_EXISTING_USER_RESPONSE:
				case AUTHN_STATUS_CREDS_CHECK_RESULT: {
					wlog("THIS SHOULDN'T HAPPEN!!!! (%s)\n", authn_status_to_str(buf.status));
					break;
				}
			}
			wlog("AUTHNNNNNNNNNNNNNNNN 4444444\n");
		}
		wlog("AUTHNNNNNNNNNNNNNNNN 5555555\n");
		close(connecting_sock_fd);
		if ( recvf_len == -1) pfail("authn recv");
	}

	pthread_exit("authentication_server_thread exited normally");
}

void *search_server_routine(void *arg) {
	wlog("search_endpoint 0 %s\n", (char *)arg);

	size_t recvf_len, sendto_len;
	struct sockaddr_in6 *si_me;
	search_buf_t buf;
	struct sockaddr_in6 si_search_other;
	socklen_t search_slen = SZ_SOCKADDR_IN6;

	search_sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if ( search_sock_fd == -1 ) pfail("socket");
	wlog("search_endpoint 1 %d\n", search_sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	char search_port[10];
	get_search_port_as_str(search_port);
	str_to_addr((struct sockaddr**)&si_me, NULL, search_port, AF_INET6, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	wlog("search_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(search_sock_fd, (struct sockaddr*)si_me, SZ_SOCKADDR_IN6);
	if ( br == -1 ) pfail("search bind");
	wlog("search_endpoint 3 %d\n", br);

	while (search_server_running) {
		recvf_len = recvfrom(search_sock_fd, &buf, SZ_SRCH_BF, 0, (struct sockaddr*)&si_search_other, &search_slen);
		if ( recvf_len == -1) pfail("recvfrom");

		char ip_str[INET6_ADDRSTRLEN];
		unsigned short port;
		unsigned short family;
		// void *addr = &(si_chat_other.sin_addr);
		// inet_ntop( AF_INET, &(si_chat_other.sin_addr), ip_str, sizeof(ip_str) );
		addr_to_str_short((struct sockaddr*)&si_search_other, ip_str, &port, &family);
		wlog("SEARCH received packet (%zu bytes) from %s port%d %d\n", recvf_len, ip_str, port, family);

		// TODO we should probably handle packets with a thread pool
		// so that the next recvfrom isn't blocked by the below code
// start_switch:
		switch(buf.status) {
			case SEARCH_STATUS_USERNAME: {
				wlog("SEARCH_STATUS_USERNAME from %s %s port%d %d (%d)\n", buf.id, ip_str, port, family, ntohs(buf.main_port));
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("SEARCH_STATUS_USERNAME no hn for user (%s)\n", buf.id);
					break;
				}

				// struct sockaddr si_search_other_copy = si_search_other;
				// switch (si_search_other.sa_family) {
				// 	case AF_INET: {
				// 		struct sockaddr_in *sa4 = (struct sockaddr_in*)&si_search_other_copy;
				// 		sa4->sin_port = buf.main_port;
				// 		break;
				// 	}
				// 	case AF_INET6: {
						// struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)&si_search_other_copy;
						// sa6->sin6_port = buf.main_port;
				// 		break;
				// 	}
				// 	default: {
				// 		wlog("SEARCH_STATUS_USERNAME: A problem occurred:"
				// 			" si_search_other.sa_family is neither AF_INET nor AF_INET6\n");
				// 		goto start_switch;
				// 	}
				// }
				struct sockaddr_in6 si_search_other_copy = {0};
				memcpy(&si_search_other_copy, &si_search_other, SZ_SOCKADDR_IN6);
				si_search_other_copy.sin6_port = buf.main_port;
				char wa[256] = {0};
				unsigned short wp;
				unsigned short wf;
				addr_to_str_short((struct sockaddr*)&si_search_other_copy, wa, &wp, &wf);
				wlog("SEARCH_STATUS_USERNAME-WWW-111 (%s)(%d)(%d)\n", wa, wp, wf);
				addr_to_str_short((struct sockaddr*)&si_search_other, wa, &wp, &wf);
				wlog("SEARCH_STATUS_USERNAME-WWW-222 (%s)(%d)(%d)\n", wa, wp, wf);
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_search_other_copy, SERVER_SEARCH);
				if (!n) {
					wlog("SEARCH_STATUS_USERNAME No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("SEARCH_STATUS_USERNAME with non-matching authn_token\n");
					break;
				}
				int number_of_search_results = 0;
				search_buf_t rbuf = {0};
				rbuf.status = SEARCH_STATUS_USERNAME_RESPONSE;
				hash_node_t *search_results = search_for_user(&hashtbl, buf.search_text, &number_of_search_results);
				for (int j = 0; j < number_of_search_results; j++) {
					strcpy(rbuf.search_results[j], search_results->username);
					search_results++;
				}
				rbuf.number_of_search_results = number_of_search_results;
				sendto_len = sendto(search_sock_fd, &rbuf, SZ_SRCH_BF, 0, (struct sockaddr*)&si_search_other, search_slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				// TODO free(search_results);
				break;
			}
			default: {
				break;
			}
		}
	}

	pthread_exit("search_server_routine exited normally");
}

void *main_server_endpoint(void *arg) {
	wlog("main_server_endpoint 0 %s %zu %zu %zu %zu\n", (char *)arg,
		SZ_NODE, sizeof(node_t),
		SZ_NODE_BF, sizeof(node_buf_t));

	struct sockaddr_in6 si_other = {0};
	socklen_t main_slen = SZ_SOCKADDR_IN6;
	size_t recvf_len, sendto_len;
	struct sockaddr_in6 *si_me;
	node_buf_t buf = {0};
	// nodes = malloc(SZ_LINK_LIST);
	// memset(nodes, '\0', SZ_LINK_LIST);

	sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if ( sock_fd == -1 ) pfail("socket");
	wlog("main_server_endpoint 1 %d\n", sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	char wain_port[10];
	get_wain_port_as_str(wain_port);
	str_to_addr((struct sockaddr**)&si_me, NULL, wain_port, AF_INET6, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str((struct sockaddr*)si_me, me_ip_str, me_port, me_fam);
	wlog("main_server_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(sock_fd, (struct sockaddr*)si_me, sizeof(*si_me));
	if ( br == -1 ) pfail("main bind");
	wlog("main_server_endpoint 3 %d\n", br);

	while (main_server_running) {
		recvf_len = recvfrom(sock_fd, &buf, SZ_NODE_BF, 0, (struct sockaddr*)&si_other, &main_slen);
		if ( recvf_len == -1) pfail("recvfrom");

		char ip_str[INET6_ADDRSTRLEN];
		unsigned short port;
		unsigned short family;
		// void *addr = &(si_other.sin_addr);
		// inet_ntop( AF_INET, &(si_other.sin_addr), ip_str, sizeof(ip_str) );
		addr_to_str_short((struct sockaddr*)&si_other, ip_str, &port, &family);
		if (buf.status != STATUS_STAY_IN_TOUCH)
			wlog("MAIN received packet (%zu bytes) from %s port%d %d\n", recvf_len, ip_str, port, family);

		// TODO we should probably handle packets with a thread pool
		// so that the next recvfrom isn't blocked by the below code
		switch(buf.status) {
			case STATUS_INIT_NODE: {
				wlog("STATUS_INIT_NODE %s %s %d\n", buf.id, ip_str, port);
				token_node_t *tn = lookup_token_node(&token_tbl, buf.authn_token);
				if (!tn) {
					// TODO handle this
					wlog("STATUS_INIT_NODE No token node found\n");
					break;
				}
				remove_token_node(&token_tbl, buf.authn_token);
				free(tn); // TODO actually this free should take place in remove_token_node, right?
				hash_node_t *hn = lookup_user(&hashtbl, buf.id);
				if (!hn) {
					// TODO handle this
					wlog("STATUS_INIT_NODE No hashnode found for (%s)\n", buf.id);
					break;
				}
				// TODO We must add a check here to see if this new node
				// already exists in our linked list. If it does exist, it
				// might be legit, ex: user terminated app and app didn't
				// get a chance to perform signout. If so, how to 
				// handle that?
				node_t *new_tail;
				// TODO Add a get_new_head
				// Since the user just signed in from this device,
				// it will probably get the most use and hence should
				// be the head
				get_new_tail(hn->nodes, &new_tail);
				memset(new_tail->authn_token, '\0', AUTHEN_TOKEN_LEN);
				memcpy(new_tail->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN);
				new_tail->int_or_ext = EXTERNAL_ADDR;
				new_tail->status = STATUS_NEW_NODE;
				// switch (si_other.sa_family) {
				// 	case AF_INET: {
				// 		struct sockaddr_in *sai4 = (struct sockaddr_in*)&si_other;
				// 		new_tail->external_ip4 = sai4->sin_addr.s_addr;
				// 		new_tail->external_port = sai4->sin_port;
				// 		new_tail->internal_ip4 = buf.ip4;
				// 		new_tail->internal_port = buf.port;
				// 		break;
				// 	}
				// 	case AF_INET6: {
						struct sockaddr_in6 *sai6 = (struct sockaddr_in6*)&si_other;
						memcpy(new_tail->external_ip6, sai6->sin6_addr.s6_addr, 16);
						new_tail->external_port = sai6->sin6_port;
						memcpy(new_tail->internal_ip6, buf.ip6, 16);
						new_tail->internal_port = buf.port;
				// 		break;
				// 	}
				// 	default: {
				// 		wlog("We received STATUS_INIT_NODE with invalid family %d\n",
				// 			si_other.sa_family);
				// 		continue;
				// 	}
				// }
				new_tail->external_family = sa_fam_to_sup_fam(si_other.sin6_family);
				if (new_tail->external_family == SUP_AF_INET_6) {
					int i = is_it_actually_ipv4(sai6->sin6_addr.s6_addr);
					if (i) new_tail->external_family = SUP_AF_4_via_6;
				}
				new_tail->internal_family = buf.family;
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				wlog("STATUS_INIT_NODE (%s)(%d)\n", n?"SUCCESSFULLY ADDED":"FAILED ADDING", hn->nodes->node_count);
				node_buf_t *new_tail_buf;
				node_external_to_node_buf(new_tail, &new_tail_buf, hn->username);
				sendto_len = sendto(sock_fd, new_tail_buf, SZ_NODE_BF, 0, (struct sockaddr*)&si_other, main_slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				wlog("Sendto %zu %d\n", sendto_len, new_tail->external_family);
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
				contacts_perform(hn->contacts, notify_contact_of_new_node, new_tail, hn->username, &si_other);
				// TODO notify new_node of itself i.e. the other nodes in hn->nodes
				break;
			}
			case STATUS_STAY_IN_TOUCH: {
				// wlog("STATUS_STAY_IN_TOUCH from %s port%d %d %d\n", ip_str, port,
				// 	family, STATUS_STAY_IN_TOUCH_RESPONSE);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_STAY_IN_TOUCH no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_STAY_IN_TOUCH No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_STAY_IN_TOUCH with non-matching authn_token\n");
					break;
				}
				buf.status = STATUS_STAY_IN_TOUCH_RESPONSE;
				sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, (struct sockaddr*)&si_other, main_slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				break;
			}
			case STATUS_DEINIT_NODE: {
				wlog("STATUS_DEINIT_NODE from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_DEINIT_NODE no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_DEINIT_NODE No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_DEINIT_NODE with non-matching authn_token\n");
					break;
				}
				contacts_perform(hn->contacts, notify_contact_of_deinit_node, n, hn->username, &si_other);

				wlog("STATUS_DEINIT_NODE before(%d)\n", hn->nodes->node_count);
				for (node_t *no = hn->nodes->head; no!=NULL; no=no->next) {
					wlog("(%d):(%d):(%d)\n", no->external_ip4, ntohs(no->external_port), ntohs(no->external_chat_port));
				}

				// TODO you can just remove (n) since we already have it
				remove_node_with_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				wlog("STATUS_DEINIT_NODE after(%d)\n", hn->nodes->node_count);
				for (node_t *no = hn->nodes->head; no!=NULL; no=no->next) {
					wlog("(%d):(%d):(%d)\n", no->external_ip4, ntohs(no->external_port), ntohs(no->external_chat_port));
				}

				break;
			}
			case STATUS_REQUEST_ADD_CONTACT_REQUEST: {
				wlog("STATUS_REQUEST_ADD_CONTACT_REQUEST from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_REQUEST_ADD_CONTACT_REQUEST no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_REQUEST_ADD_CONTACT_REQUEST No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_REQUEST_ADD_CONTACT_REQUEST with non-matching authn_token\n");
					break;
				}

				hash_node_t *hn_request_to = lookup_user(&hashtbl, buf.other_id);
				if (!hn_request_to) break;
				if (!hn_request_to->nodes) {
					// TODO handle this better
					request_to_add_contact(&hashtbl, hn->username, hn_request_to->username);
					break;
				}

				for (node_t *n = hn_request_to->nodes->head; n != NULL; n = n->next) {
					struct sockaddr *n_addr = NULL;
					node_to_external_addr(n, &n_addr);

					node_buf_t nb = {0};
					nb.status = STATUS_REQUEST_ADD_CONTACT_REQUEST;
					strcpy(nb.other_id, hn->username);
					
					sendto_len = sendto(sock_fd, &nb, SZ_NODE_BF, 0, n_addr, main_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}
				}
				
				break;
			}
			case STATUS_REQUEST_ADD_CONTACT_ACCEPT: {
				wlog("STATUS_REQUEST_ADD_CONTACT_ACCEPT from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_REQUEST_ADD_CONTACT_ACCEPT no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_REQUEST_ADD_CONTACT_ACCEPT No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_REQUEST_ADD_CONTACT_ACCEPT with non-matching authn_token\n");
					break;
				}

				hash_node_t *hn_request_to = lookup_user(&hashtbl, buf.other_id);
				if (!hn_request_to) break;

				contact_t *c1 = add_contact_to_hashtbl(&hashtbl, hn->username, hn_request_to->username);
				contact_t *c2 = add_contact_to_hashtbl(&hashtbl, hn_request_to->username, hn->username);

				if (!c1 || !c2) {
					// TODO handle this better
					break;
				}

				if (!hn_request_to->nodes) {
					// TODO handle this better
					add_accepted_contact_later(&hashtbl, hn->username, hn_request_to->username);
					break;
				}

				for (node_t *n2 = hn->nodes->head; n2 != NULL; n2 = n2->next) {
					struct sockaddr *n_addr = NULL;
					node_to_external_addr(n2, &n_addr);

					node_buf_t nb = {0};
					nb.status = STATUS_REQUEST_ADD_CONTACT_ACCEPT;
					strcpy(nb.other_id, hn_request_to->username);

					sendto_len = sendto(sock_fd, &nb, SZ_NODE_BF, 0, n_addr, main_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}

					node_buf_t contact_nb;
					contact_nb.status = STATUS_NOTIFY_EXISTING_CONTACT;
					strcpy(contact_nb.id, hn_request_to->username);
					if (sendto(sock_fd, &contact_nb, SZ_NODE_BF, 0, n_addr, main_slen)==-1)
						pfail("sendto");
				}

				for (node_t *n1 = hn_request_to->nodes->head; n1 != NULL; n1 = n1->next) {
					struct sockaddr *n_addr = NULL;
					node_to_external_addr(n1, &n_addr);

					node_buf_t nb = {0};
					nb.status = STATUS_REQUEST_ADD_CONTACT_ACCEPT;
					strcpy(nb.other_id, hn->username);

					sendto_len = sendto(sock_fd, &nb, SZ_NODE_BF, 0, n_addr, main_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}

					notify_contact_of_new_node(c2, n1, hn_request_to->username, n_addr);
					notify_contact_of_new_chat_port(c2, n1, hn_request_to->username, n_addr);
				}
				break;
			}
			case STATUS_REQUEST_ADD_CONTACT_DENIED: {
				wlog("STATUS_REQUEST_ADD_CONTACT_DENIED from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_REQUEST_ADD_CONTACT_DENIED no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_REQUEST_ADD_CONTACT_DENIED No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_REQUEST_ADD_CONTACT_DENIED with non-matching authn_token\n");
					break;
				}

				hash_node_t *hn_request_to = lookup_user(&hashtbl, buf.other_id);
				if (!hn_request_to) break;
				if (!hn_request_to->nodes) break;

				for (node_t *n = hn_request_to->nodes->head; n != NULL; n = n->next) {
					struct sockaddr *n_addr = NULL;
					node_to_external_addr(n, &n_addr);

					node_buf_t nb = {0};
					nb.status = STATUS_REQUEST_ADD_CONTACT_DENIED;
					strcpy(nb.other_id, hn->username);

					sendto_len = sendto(sock_fd, &nb, SZ_NODE_BF, 0, n_addr, main_slen);
					if (sendto_len == -1) {
						pfail("sendto");
					}
				}
				break;
			}
			case STATUS_ACQUIRED_CHAT_PORT: {
				wlog("STATUS_ACQUIRED_CHAT_PORT (%d) from %s %s port%d %d\n",
					ntohs(buf.chat_port), buf.id, ip_str, port, family);

				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_ACQUIRED_CHAT_PORT no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_ACQUIRED_CHAT_PORT No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_ACQUIRED_CHAT_PORT with non-matching authn_token\n");
					break;
				}

				// TODO we are duplicating calls to find_node_from_sockaddr
				node_t *peer_with_new_chat_port = find_node_from_sockaddr(hn->nodes,
					(struct sockaddr*)&si_other,
					SERVER_MAIN);
				if (peer_with_new_chat_port) {
					peer_with_new_chat_port->external_chat_port = buf.chat_port;
					peer_with_new_chat_port->internal_chat_port = buf.chat_port;
					// TODO how to handle internal_chat_port here?
					// Just use buf.int_or_ext?
					contacts_perform(hn->contacts,
						notify_contact_of_new_chat_port,
						peer_with_new_chat_port, hn->username, &si_other);
				}
				break;
			}
			case STATUS_SIGN_OUT: {
				wlog("STATUS_SIGN_OUT from %s %s port%d %d\n", buf.id, ip_str, port, family);
				hash_node_t *hn = lookup_user_from_id(&hashtbl, buf.id);
				if (!hn) {
					wlog("STATUS_SIGN_OUT no hn for user (%s)\n", buf.id);
					break;
				}
				node_t *n = find_node_from_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				if (!n) {
					wlog("STATUS_SIGN_OUT No node found for addr %s %s port%d %d\n",
						buf.id, ip_str, port, family);
					break;
				}
				if (memcmp(n->authn_token, buf.authn_token, AUTHEN_TOKEN_LEN) != 0) {
					wlog("STATUS_SIGN_OUT with non-matching authn_token\n");
					break;
				}
				contacts_perform(hn->contacts, notify_contact_of_deinit_node, n, hn->username, &si_other);

				wlog("STATUS_SIGN_OUT before(%d)\n", hn->nodes->node_count);
				for (node_t *no = hn->nodes->head; no!=NULL; no=no->next) wlog("(%d)", no->external_ip4);
				wlog("\n");
				remove_node_with_sockaddr(hn->nodes, (struct sockaddr*)&si_other, SERVER_MAIN);
				wlog("STATUS_SIGN_OUT after(%d)\n", hn->nodes->node_count);
				for (node_t *no = hn->nodes->head; no!=NULL; no=no->next) wlog("(%d)", no->external_ip4);
				wlog("\n");
				break;
			}
			default: {
				char *buf_char = (char *) &buf;
				wlog("None of the above - buf.status -: %d -: %s\n", buf.status, buf_char);
				break;
			}
		}

		// wlog("Now we have %d nodes\n", nodes->node_count);
		// And we go back to listening. Notice that since UDP has no notion
        	// of connections, we can use the same socket to listen for data
        	// from different clients.
	}

	close(sock_fd);
	freehashtable(&hashtbl);

	pthread_exit("main_server_thread exited normally");
}

void *chat_endpoint(void *msg) {
	wlog("chat_endpoint 0 %s\n", (char *)msg);

	size_t recvf_len, sendto_len;
	struct sockaddr_in6 *si_me;
	chat_buf_t buf;
	memset(&buf, '\0', SZ_CH_BF);
	struct sockaddr_in6 si_chat_other;
	memset(&si_chat_other, '\0', SZ_SOCKADDR_IN6);
	socklen_t chat_slen = SZ_SOCKADDR_IN6;

	chat_sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if ( chat_sock_fd == -1 ) pfail("socket");
	wlog("chat_endpoint 1 %d\n", chat_sock_fd);

	// si_me stores our local endpoint. Remember that this program
	// has to be run in a network with UDP endpoint previously known
	// and directly accessible by all clients. In simpler terms, the
	// server cannot be behind a NAT.
	char chat_port[10];
	get_chat_port_as_str(chat_port);
	str_to_addr((struct sockaddr**)&si_me, NULL, chat_port, AF_INET6, SOCK_DGRAM, AI_PASSIVE);
	char me_ip_str[256];
	char me_port[20];
	char me_fam[5];
	addr_to_str( (struct sockaddr*)si_me, me_ip_str, me_port, me_fam );
	wlog("chat_endpoint 2 %s %s %s %zu\n", me_ip_str, me_port, me_fam, sizeof(*si_me));

	int br = bind(chat_sock_fd, (struct sockaddr*)si_me, SZ_SOCKADDR_IN6);
	if ( br == -1 ) pfail("chat bind");
	wlog("chat_endpoint 3 (%d)(%d)(%lu)\n", chat_sock_fd, br, SZ_CH_BF);

	while (chat_running) {
		recvf_len = recvfrom(chat_sock_fd, &buf, SZ_CH_BF, 0, (struct sockaddr *)&si_chat_other, &chat_slen);
		if ( recvf_len == -1) {
			char w[256];
			sprintf(w, "chattttt recvfrom (%d)", chat_sock_fd);
			pfail(w);
		}

		char ip_str[INET6_ADDRSTRLEN];
		unsigned short port;
		unsigned short family;
		addr_to_str_short((struct sockaddr *)&si_chat_other, ip_str, &port, &family);
		if (buf.status != CHAT_STATUS_STAY_IN_TOUCH)
			wlog("CHATTTT received packet (%d)(%s) (%zu bytes) from %s port%d %d\n", buf.status, chat_status_to_str(buf.status),
				recvf_len, ip_str, port, family);

		// TODO we should probably handle packets with a thread pool
		// so that the next recvfrom isn't blocked by the below code
		switch(buf.status) {
			case CHAT_STATUS_INIT: {
				wlog("CHAT_STATUS_INIT from %s port%d %d\n", ip_str, port, family);
				buf.status = CHAT_STATUS_NEW;
				buf.family = sa_fam_to_sup_fam(si_chat_other.sin6_family);
				switch (si_chat_other.sin6_family) {
					case AF_INET: {
						buf.ip4 = ((struct sockaddr_in *)&si_chat_other)->sin_addr.s_addr;
						buf.port = ((struct sockaddr_in *)&si_chat_other)->sin_port;
						break;
					}
					case AF_INET6: {
						memcpy(buf.ip6, ((struct sockaddr_in6 *)&si_chat_other)->sin6_addr.s6_addr,
							sizeof(unsigned char[16]));
						buf.port = ((struct sockaddr_in6 *)&si_chat_other)->sin6_port;
						break;
					}
					default: {
						wlog("CHAT_STATUS_INIT si_chat_other.sa_family is not good %d\n",
							si_chat_other.sin6_family);
						continue;
					}
				}
				sendto_len = sendto(chat_sock_fd, &buf, sizeof(buf), 0, (struct sockaddr *)&si_chat_other, chat_slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				wlog("Sendto %zu %d\n", sendto_len, buf.family);
				break;
			}
			case CHAT_STATUS_STAY_IN_TOUCH: {
				// wlog("CHAT_STATUS_STAY_IN_TOUCH from %s port%d %d\n", ip_str, port, family);
				buf.status = CHAT_STATUS_STAY_IN_TOUCH_RESPONSE;
				sendto_len = sendto(chat_sock_fd, &buf, sizeof(buf), 0, (struct sockaddr *)&si_chat_other, chat_slen);
				if (sendto_len == -1) {
					pfail("sendto");
				}
				break;
			}
			default: {
				break;
			}
		}
	}

	pthread_exit("chat_hp_thread exiting normally");
}

int main(int argc, char **argv) {
	printf("the_server is initializing...\n");

	if (argc < 2) {
		printf("Only (%d) argument(s) given. You must provide atleast 2.\n", argc);
		exit(1);
	}

	char *arg_env = argv[1];
	set_environment_from_str_with_logging(arg_env, 1);
	get_environment_as_str(environment_str);
	wlog("the_server environment is (%s)\n", environment_str);
	server_ip_str = get_server_ip_as_str();
	wlog("the_server server_ip_str (%s)\n", server_ip_str);
	printf("the_server is starting...\n");

	wlog("the_server main 0 %zu %zu\n", sizeof(STATUS_TYPE), sizeof(struct node));

	// Get the keys
	int ckr = collect_rsa_keys();
	if (ckr == -1) {
		wlog("ERROR collecting RSA keys\n");
		exit(-1);
	}

	ckr = collect_aes_key_and_iv();
	if (ckr == -1) {
		wlog("ERROR collecting AES key or IV\n");
		exit(-1);
	}

	// Load up the hashtbl
	load_hashtbl_from_db();

	// Fire up the authentication server
	char *authn_exit_msg;
	int atcr = pthread_create(&authentication_server_thread, NULL,
		authentication_server_endpoint, (void *)"authN_server_thread");
	if (atcr) {
		wlog("ERROR starting authentication_server_thread: %d\n", atcr);
		exit(-1);
	}

	char *search_exit_msg;
	int stcr = pthread_create(&search_server_thread, NULL, search_server_routine, "");
	if (stcr) {
		wlog("ERROR starting search_server_thread: %d\n", stcr);
		exit(-1);
	}

	char *thread_exit_msg;
	int pcr = pthread_create(&main_server_thread, NULL, main_server_endpoint, (void *)"main_server_thread");
	if (pcr) {
		wlog("ERROR starting main_server_thread: %d\n", pcr);
		exit(-1);
	}

	char *chat_thread_exit_msg;
	int cpcr = pthread_create(&chat_thread, NULL, chat_endpoint, (void *)"chap_hp_thread");
	if (cpcr) {
		wlog("ERROR starting chat_hp_thread: %d\n", cpcr);
		exit(-1);
	}

	pthread_join(authentication_server_thread, (void**)&authn_exit_msg);
	pthread_join(search_server_thread, (void**)&search_exit_msg);
	pthread_join(main_server_thread,(void**)&thread_exit_msg);
	pthread_join(chat_thread,(void**)&chat_thread_exit_msg);

	wlog("Wrapping up sign_in_service: %s\n", thread_exit_msg);
	return 0;
}
