#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/err.h>

#include "udp_client.h"
#include "hashtable.h"
#include "common.h"
#include "crypto_wrapper.h"

#define DEFAULT_OTHER_ADDR_LEN sizeof(struct sockaddr_in6)

NODE_USER_STATUS node_user_status;
char username[MAX_CHARS_USERNAME] = "Rupert Humperdink";
char password[MAX_CHARS_PASSWORD] = "A bottle of bordeaux please";
unsigned char authentication_token[AUTHEN_TOKEN_LEN];

void send_hole_punch(node_t *peer);
void *chat_hole_punch_thread(void *peer_to_hole_punch);
void send_chat_hole_punch(node_t *peer);
void init_chat_hp();
void *chat_hp_server(void *w);

hash_node_t self;
char *rsa_public_key, *rsa_private_key, *server_rsa_pub_key;
unsigned char *aes_key;
unsigned char *aes_iv;

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

// The AuthN server
struct sockaddr *sa_authn_server;
socklen_t authn_server_socklen = 0;
size_t authn_sendto_len, authn_recvf_len;

// The search server
struct sockaddr *sa_search_server;
socklen_t search_server_socklen = 0;
size_t search_sendto_len, search_recvf_len;

// The chat server
struct sockaddr *sa_chat_server;
char chat_server_internal_ip[INET6_ADDRSTRLEN];
char chat_server_internal_port[20];
char chat_server_internal_family[20];
socklen_t chat_server_socklen = 0;

// The socket file descriptors
int authn_sock_fd;
int sock_fd;
int chat_sock_fd;
int search_sock_fd;

// Threads
pthread_t wain_thread;
pthread_t authn_thread;
pthread_t search_thread;

// Runnings
int wain_running = 1;
int authn_running = 1;
int stay_in_touch_running = 1;
int chat_stay_in_touch_running = 1;
int chat_server_conn_running = 1;
int search_running = 0;

// Misc
int authn_thread_has_started = 0;
int wain_thread_has_started = 0;
int search_thread_has_started = 0;

// function pointers
void (*rsakeypair_generated_cb)(const char *rsa_pub_key, const char *rsa_pri_key) = NULL;
void (*rsa_response_cb)(char *server_rsa_pub_key) = NULL;
void (*aes_key_created_cb)(unsigned char[NUM_BYTES_AES_KEY]) = NULL;
void (*aes_response_cb)(NODE_USER_STATUS) = NULL;
void (*creds_check_result_cb)(AUTHN_CREDS_CHECK_RESULT, char *username, char *password, unsigned char[AUTHEN_TOKEN_LEN]) = NULL;
void (*self_info_cb)(char *, unsigned short, unsigned short, unsigned short) = NULL;
void (*server_info_cb)(SERVER_TYPE, char *) = NULL;
void (*socket_created_cb)(int) = NULL;
void (*socket_bound_cb)(void) = NULL;
void (*sendto_succeeded_cb)(size_t) = NULL;
void (*recd_cb)(SERVER_TYPE, size_t, socklen_t, char *) = NULL;
void (*notify_existing_contact_cb)(char *) = NULL;
void (*stay_touch_recd_cb)(SERVER_TYPE) = NULL;
void (*coll_buf_cb)(char *) = NULL;
void (*new_client_cb)(SERVER_TYPE, char *) = NULL;
void (*confirmed_client_cb)(void) = NULL;
void (*hole_punch_sent_cb)(char *, int) = NULL;
void (*contact_deinit_node_cb)(char *) = NULL;
void (*add_contact_request_cb)(char *) = NULL;
void (*contact_request_accepted_cb)(char *) = NULL;
void (*contact_request_declined_cb)(char *) = NULL;
void (*new_peer_cb)(char *) = NULL;
void (*confirmed_peer_while_punching_cb)(SERVER_TYPE) = NULL;
void (*from_peer_cb)(SERVER_TYPE, char *) = NULL;
void (*chat_msg_cb)(char *) = NULL;
void (*unhandled_response_from_server_cb)(int) = NULL;
void (*username_results_cb)(char search_results[MAX_SEARCH_RESULTS][MAX_CHARS_USERNAME], int number_of_search_results) = NULL;

void pfail(char *w) {
	printf("pfail 0\n");
	perror(w);
	exit(1);
}

void create_aes_iv() {
	unsigned char iv[NUM_BYTES_AES_IV];
	memset(iv, '\0', NUM_BYTES_AES_IV);
	if (!RAND_bytes(iv, sizeof(iv))) {
		printf("RAND_bytes failed for iv\n");
		ERR_print_errors_fp(stdout);
		return;
	}

	free(aes_iv);
	aes_iv = malloc(NUM_BYTES_AES_IV);
	memset(aes_iv, '\0', NUM_BYTES_AES_IV);
	memcpy(aes_iv, iv, NUM_BYTES_AES_IV);
}

void create_aes_key_iv() {
	create_aes_iv();
	if (aes_key) return;

	unsigned char symmetric_key[NUM_BYTES_AES_KEY];
	memset(symmetric_key, '\0', NUM_BYTES_AES_KEY);

	if (!RAND_bytes(symmetric_key, sizeof(symmetric_key))) {
		printf("RAND_bytes failed for symmetric_key\n");
		ERR_print_errors_fp(stdout);
	}

	aes_key = malloc(NUM_BYTES_AES_KEY);
	memset(aes_key, '\0', NUM_BYTES_AES_KEY);
	memcpy(aes_key, symmetric_key, NUM_BYTES_AES_KEY);
	if (aes_key_created_cb) aes_key_created_cb(aes_key);
}

int send_user(NODE_USER_STATUS nus, char *usernm, char *pw) {
	if (!usernm || !pw) return -1;

	node_user_status = nus;
	authn_buf_t buf;
	memset(&buf, '\0', SZ_AUN_BF);
	switch (node_user_status) {
		case NODE_USER_STATUS_NEW_USER: {
			buf.status = AUTHN_STATUS_NEW_USER;
			break;
		}
		case NODE_USER_STATUS_EXISTING_USER: {
			buf.status = AUTHN_STATUS_EXISTING_USER;
			break;
		}
		case NODE_USER_STATUS_UNKNOWN: {
			return -1;
		}
	}

	memset(buf.id, '\0', MAX_CHARS_USERNAME);
	memset(buf.pw, '\0', MAX_CHARS_PASSWORD);
	memset(username, '\0', MAX_CHARS_USERNAME);
	memset(password, '\0', MAX_CHARS_PASSWORD);

	memcpy(buf.id, usernm, strlen(usernm));
	memcpy(buf.pw, pw, strlen(pw));
	memcpy(username, usernm, strlen(usernm));
	memcpy(password, pw, strlen(pw));

	unsigned char cipherbuf[SZ_AUN_BF + AES_PADDING];
	memset(cipherbuf, '\0', SZ_AUN_BF + AES_PADDING);
	int cipherbuf_len = aes_encrypt((unsigned char*)&buf, SZ_AUN_BF, aes_key, aes_iv, cipherbuf);

	authn_buf_encrypted_t buf_enc;
	memset(&buf_enc, '\0', SZ_AE_BUF);
	buf_enc.status = AUTHN_STATUS_ENCRYPTED;
	memset(buf_enc.encrypted_buf, '\0', SZ_AUN_BF + AES_PADDING);
	memcpy(buf_enc.encrypted_buf, cipherbuf, cipherbuf_len);
	buf_enc.encrypted_len = cipherbuf_len;

	stay_in_touch_running = 1;
	chat_stay_in_touch_running = 1;
	chat_server_conn_running = 1;

	if (!authn_running) {
		authn_running = 1;
		wain_running = 1;
		authn(nus, usernm, pw, buf.status, rsa_public_key, rsa_private_key, aes_key,
			rsakeypair_generated_cb,
			recd_cb,
			rsa_response_cb,
			aes_key_created_cb,
			aes_response_cb,
			creds_check_result_cb);

		int authn_retries = 0;
		while (!authn_thread_has_started || !wain_thread_has_started) {
			usleep(MICROSECONDS_TO_WAIT_BTWN_AUTHN_ATTEMPTS);
			if (++authn_retries >= AUTHN_RETRY_ATTEMPTS) {
				printf("Couldn't restart authn_thread\n");
				return -1;
			}
		}
	}

	// if (!wain_running) {
	// 	wain_running = 1;
	// 	wain(self_info_cb,
	// 		socket_created_cb,
	// 		socket_bound_cb,
	// 		sendto_succeeded_cb,
	// 		coll_buf_cb,
	// 		new_client_cb,
	// 		confirmed_client_cb,
	// 		notify_existing_contact_cb,
	// 		stay_touch_recd_cb,
	// 		new_peer_cb,
	// 		hole_punch_sent_cb,
	// 		confirmed_peer_while_punching_cb,
	// 		from_peer_cb,
	// 		chat_msg_cb,
	// 		unhandled_response_from_server_cb,
	// 		NULL,
	// 		NULL);

	// 	int wain_retries = 0;
	// 	while (!wain_thread_has_started) {
	// 		usleep(10*1000); // 10 milliseconds
	// 		if (++wain_retries >= 100) {
	// 			printf("Couldn't restart wain_thread\n");
	// 			return -1;
	// 		}
	// 	}
	// }

	authn_sendto_len = sendto(authn_sock_fd, &buf_enc, SZ_AE_BUF, 0,
		sa_authn_server, authn_server_socklen);
	if (authn_sendto_len == -1) {
		char w[256];
		sprintf(w, "authn sendto failed with %zu", authn_sendto_len);
		pfail(w);
	}

	return 0;
}

void *authn_thread_routine(void *arg) {
	AUTHN_STATUS auth_status = *(AUTHN_STATUS *)arg;
	printf("authn_thread_routine (%d)\n", auth_status);

	char authn_server_ip[INET6_ADDRSTRLEN];
	char authn_server_port[20];
	char authn_server_family[20];
	char wes[256];
	authn_buf_t buf;
	struct sockaddr sa_authn_other;
	char authn_other_ip[INET6_ADDRSTRLEN];
	char authn_other_port[20];
	char authn_other_family[20];
	socklen_t authn_other_socklen = DEFAULT_OTHER_ADDR_LEN;
	char wayne[256];

	authn_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (authn_sock_fd == -1) {
		printf("There was a problem creating the authn socket\n");
	}

	// Setup server
	char auth_port[10];
	sprintf(auth_port, "%d", AUTHENTICATION_PORT);
	str_to_addr(&sa_authn_server, "142.105.56.124", auth_port, AF_INET, SOCK_DGRAM, 0);
	authn_server_socklen = sa_authn_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	addr_to_str(sa_authn_server, authn_server_ip, authn_server_port, authn_server_family);
	sprintf(wes, "The authn server %s port%s %s %u",
		authn_server_ip,
		authn_server_port,
		authn_server_family,
		authn_server_socklen);
	if (server_info_cb) server_info_cb(SERVER_AUTHN, wes);

	memset(&buf, '\0', SZ_AUN_BF);
	buf.status = auth_status;
	memset(buf.rsa_pub_key, '\0', RSA_PUBLIC_KEY_LEN);
	if (rsa_public_key) memcpy(buf.rsa_pub_key, rsa_public_key, strlen(rsa_public_key));

	authn_sendto_len = sendto(authn_sock_fd, &buf, SZ_AUN_BF, 0, sa_authn_server, authn_server_socklen);
	if (authn_sendto_len == -1) {
		char w[256];
		sprintf(w, "authn sendto failed with %zu", authn_sendto_len);
		pfail(w);
	}

	if (authn_running) authn_thread_has_started = 1;
	while (authn_running) {
		authn_recvf_len = recvfrom(authn_sock_fd, &buf, SZ_AUN_BF, 0, &sa_authn_other, &authn_other_socklen);
		if (authn_recvf_len == -1) {
			char w[256];
			sprintf(w, "authn recvfrom failed with %zu", authn_recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_authn_other, authn_other_ip, authn_other_port, authn_other_family);
		sprintf(wayne, "(%s) %s port%s %s", authn_status_to_str(buf.status),
			authn_other_ip, authn_other_port, authn_other_family);
		if (recd_cb) recd_cb(SERVER_AUTHN, authn_recvf_len, authn_other_socklen, wayne);
		authn_other_socklen = DEFAULT_OTHER_ADDR_LEN;

		switch (buf.status) {
			case AUTHN_STATUS_ENCRYPTED: {
				// TODO
				break;
			}
			case AUTHN_STATUS_RSA_SWAP_RESPONSE: {
				server_rsa_pub_key = malloc(RSA_PUBLIC_KEY_LEN);
				memset(server_rsa_pub_key, '\0', RSA_PUBLIC_KEY_LEN);
				memcpy(server_rsa_pub_key, buf.rsa_pub_key, RSA_PUBLIC_KEY_LEN);
				if (rsa_response_cb) rsa_response_cb(server_rsa_pub_key);

				create_aes_key_iv();
				RSA *rsa_pub_key;
				load_public_key_from_str(&rsa_pub_key, server_rsa_pub_key);
				int result_len = 0;
				unsigned char rsa_encrypted_aes_key[NUM_BYTES_RSA_ENCRYPTED_DATA];
				memset(rsa_encrypted_aes_key, '\0', NUM_BYTES_RSA_ENCRYPTED_DATA);
				printf("Attempting to encrypt (%d) bytes\n", NUM_BYTES_AES_KEY);
				rsa_encrypt(rsa_pub_key, aes_key, NUM_BYTES_AES_KEY, rsa_encrypted_aes_key, &result_len);
				printf("rsa_encrypted:(%s)(%d)\n", rsa_encrypted_aes_key, result_len);

				memset(&buf, '\0', SZ_AUN_BF);
				buf.status = AUTHN_STATUS_AES_SWAP;
				// TODO encrypt AES key with RSA key before sending
				memset(buf.aes_key, '\0', NUM_BYTES_RSA_ENCRYPTED_DATA);
				memcpy(buf.aes_key, rsa_encrypted_aes_key, result_len);
				memset(buf.aes_iv, '\0', NUM_BYTES_AES_IV);
				memcpy(buf.aes_iv, aes_iv, NUM_BYTES_AES_IV);

				authn_sendto_len = sendto(authn_sock_fd, &buf, SZ_AUN_BF, 0,
					sa_authn_server, authn_server_socklen);
				if (authn_sendto_len == -1) {
					char w[256];
					sprintf(w, "authn sendto failed with %zu", authn_sendto_len);
					pfail(w);
				}
				break;
			}
			case AUTHN_STATUS_AES_SWAP_RESPONSE: {
				// printf("The server's AES key (%s)\n", buf.aes_key);
				// printf("The server's AES iv (%s)\n", buf.aes_iv);
				if (aes_response_cb) aes_response_cb(node_user_status);
				char un[MAX_CHARS_USERNAME] = {0};
				char pw[MAX_CHARS_PASSWORD] = {0};
				strcpy(un, username);
				strcpy(pw, password);
				send_user(node_user_status, un, pw);
				break;
			}
			case AUTHN_STATUS_NEW_USER_RESPONSE: {
				// TODO
				break;
			}
			case AUTHN_STATUS_EXISTING_USER_RESPONSE: {
				// TODO
				break;
			}
			case AUTHN_STATUS_CREDS_CHECK_RESULT: {
				if (buf.authn_result == AUTHN_CREDS_CHECK_RESULT_GOOD)
					memcpy(authentication_token, buf.authn_token, AUTHEN_TOKEN_LEN);
				if (creds_check_result_cb)
					creds_check_result_cb(buf.authn_result, username, password, buf.authn_token);
				break;
			}
			case AUTHN_STATUS_RSA_SWAP:
			case AUTHN_STATUS_AES_SWAP:
			case AUTHN_STATUS_NEW_USER:
			case AUTHN_STATUS_EXISTING_USER:
			case AUTHN_STATUS_SIGN_OUT: {
				printf("THIS SHOULDN'T HAPPEN!!!! (%s)\n", authn_status_to_str(buf.status));
				break;
			}
		}

	}
	authn_thread_has_started = 0;
	pthread_exit("authn_thread exited normally");
}

int authn(NODE_USER_STATUS user_stat,
	const char *usernm,
	const char *passwd,
	AUTHN_STATUS auth_status,
	const char *rsa_pub_key,
	const char *rsa_pri_key,
	unsigned char *aes_k,
	void (*rsakeypair_generated)(const char *rsa_pub_key, const char *rsa_pri_key),
	void (*recd)(SERVER_TYPE, size_t, socklen_t, char *),
	void (*rsa_response)(char *server_rsa_pub_key),
	void (*aes_key_created)(unsigned char[NUM_BYTES_AES_KEY]),
	void (*aes_response)(NODE_USER_STATUS),
	void (*creds_check_result)(AUTHN_CREDS_CHECK_RESULT, char *username,
		char *password, unsigned char[AUTHEN_TOKEN_LEN])) {

	rsakeypair_generated_cb = rsakeypair_generated;
	recd_cb = recd;
	rsa_response_cb = rsa_response;
	aes_key_created_cb = aes_key_created;
	aes_response_cb = aes_response;
	creds_check_result_cb = creds_check_result;
	node_user_status = user_stat;

	memset(username, '\0', MAX_CHARS_USERNAME);
	if (usernm) {
		strcpy(username, usernm);
	}

	memset(password, '\0', MAX_CHARS_PASSWORD);
	if (passwd) {
		strcpy(password, passwd);
	}

	if (aes_k) {
		aes_key = malloc(NUM_BYTES_AES_KEY);
		memset(aes_key, '\0', NUM_BYTES_AES_KEY);
		memcpy(aes_key, aes_k, NUM_BYTES_AES_KEY);
	}

	int i;
	for (i = 0; i < NUM_BYTES_AES_KEY; i++) {
		if (i > 0) printf(":");
		printf("(%d)-(%02X)", i, aes_key[i]);
	}
	printf("\n");

	rsa_public_key = malloc(strlen(rsa_pub_key)+1);
	rsa_private_key = malloc(strlen(rsa_pri_key)+1);
	memset(rsa_public_key, '\0', strlen(rsa_pub_key)+1);
	memset(rsa_private_key, '\0', strlen(rsa_pri_key)+1);

	if (!rsa_pub_key || !rsa_pri_key) {
		char *rsa_pri = NULL, *rsa_pub = NULL;
		generate_rsa_keypair(NULL, &rsa_pri, &rsa_pub, NULL, NULL);
		// TODO handle !rsa_pub || !rsa_pri
		strcpy(rsa_public_key, rsa_pub);
		strcpy(rsa_private_key, rsa_pri);
		free(rsa_pub);
		free(rsa_pri);
		if (rsakeypair_generated_cb) rsakeypair_generated_cb(rsa_pub, rsa_pri);
	} else {
		strcpy(rsa_public_key, rsa_pub_key);
		strcpy(rsa_private_key, rsa_pri_key);
//		free((char*)rsa_pub_key);
//		free((char*)rsa_pri_key);
	}

	AUTHN_STATUS *as = malloc(sizeof(int));
	if (as) *as = auth_status;

	int atr = pthread_create(&authn_thread, NULL, authn_thread_routine, as);
	if (atr) {
		printf("ERROR in authn_thread creation; return code from pthread_create() is %d\n", atr);
		return -1;
	}
	return 0;
}

void *hole_punch_thread(void *peer_to_hole_punch) {
	node_t *peer = (node_t *)peer_to_hole_punch;
	for (int j = 0; j < HOLE_PUNCH_RETRY_ATTEMPTS; j++) {
		// Send (HOLE_PUNCH_RETRY_ATTEMPTS) datagrams, or until the peer
		// is confirmed, whichever occurs first.
		if (peer->status >= STATUS_CONFIRMED_PEER) {
			if (confirmed_peer_while_punching_cb)
				confirmed_peer_while_punching_cb(SERVER_MAIN);
			break;
		}
		send_hole_punch(peer);
		usleep(MICROSECONDS_TO_WAIT_BTWN_HOLE_PUNCH_ATTEMPTS);
	}
	pthread_exit("hole_punch_thread exiting normally");
}

void punch_hole_in_peer(SERVER_TYPE st, node_t *peer) {
	pthread_t hpt;
	void *start_routine = NULL;
	switch (st) {
		case SERVER_MAIN: {
			start_routine = hole_punch_thread;
			break;
		}
		case SERVER_CHAT: {
			start_routine = chat_hole_punch_thread;
			break;
		}
		default: return;
	}
	int pt = pthread_create(&hpt, NULL, start_routine, peer);
	if (pt) {
		printf("ERROR in punch_hole_in_peer; return code from pthread_create() is %d\n", pt);
		return;
	}
}

void send_hole_punch(node_t *peer) {
	if (!peer) return;
	// TODO set peer->status = STATUS_NEW_PEER?
	// and then set back to previous status?
	static int hpc = 0;
	struct sockaddr *peer_addr;
	socklen_t peer_socklen = 0;
	// TODO handle int_or_ext
	switch (peer->external_family) {
		case AF_INET: {
			struct sockaddr_in sa4;
			sa4.sin_family = AF_INET;
			sa4.sin_addr.s_addr = peer->external_ip4;
			sa4.sin_port = peer->external_port;
			peer_socklen = SZ_SOCKADDR_IN;
			peer_addr = (struct sockaddr*)&sa4;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 sa6;
			sa6.sin6_family = AF_INET6;
			memcpy(sa6.sin6_addr.s6_addr, peer->external_ip6, sizeof(unsigned char[16]));
			sa6.sin6_port = peer->external_port;
			peer_socklen = SZ_SOCKADDR_IN6;
			peer_addr = (struct sockaddr*)&sa6;
			break;
		}
		default: {
			printf("send_hole_punch, peer->family not well defined\n");
			return;
		}
	}
	if (sendto(sock_fd, self_external, SZ_NODE_BF, 0, peer_addr, peer_socklen) == -1)
		pfail("send_hole_punch sendto");
	char spf[256];
	char pi[INET6_ADDRSTRLEN];
	char pp[20];
	char pf[20];
	addr_to_str(peer_addr, pi, pp, pf);
	sprintf(spf, "send_hole_punch %s %s %s\n", pi, pp, pf);
	if (hole_punch_sent_cb) hole_punch_sent_cb(spf, ++hpc);
}

void ping_all_peers() {
	// nodes_min_perform(peers, send_hole_punch);
}

void *stay_in_touch_with_server_thread(void *msg) {
	printf("stay_in_touch_with_server_thread %s\n", (char*)msg);
	stay_in_touch_running = 1;
	node_buf_t w;
	strcpy(w.id, username);
	w.status = STATUS_STAY_IN_TOUCH;
	memcpy(w.authn_token, authentication_token, AUTHEN_TOKEN_LEN);

	while (stay_in_touch_running) {
		if (sendto(sock_fd, &w, SZ_NODE_BF, 0, sa_server, server_socklen) == -1)
		 	pfail("stay_in_touch_with_server_thread sendto");
		sleep(NUMBER_SECOND_BTWN_STAY_IN_TOUCH);
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
		sleep(NUMBER_SECOND_BTWN_STAY_IN_TOUCH);
	}
	pthread_exit("stay_in_touch_with_chat_server_thread exited normally");
}

void stay_in_touch_with_server(SERVER_TYPE st) {
	pthread_t sitt;
	char *w = "stay_in_touch_with_server";
	void *start_routine = NULL;
	switch (st) {
		case SERVER_MAIN: {
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

void *wain_thread_routine(void *arg) {
	printf("STARTING.....%s\n", arg);

	// Other (server or peer in recvfrom)
	struct sockaddr sa_other;
	char other_ip[INET6_ADDRSTRLEN];
	char other_port[20];
	char other_family[20];
	socklen_t other_socklen = DEFAULT_OTHER_ADDR_LEN;

	// Self
	get_if_addr(&sa_self_internal, &sz_sa_self_internal, self_internal_ip);
	addr_to_node_buf(sa_self_internal, &self_internal, STATUS_INIT_NODE, 0, username);
	memcpy(self_internal->authn_token, authentication_token, AUTHEN_TOKEN_LEN);

	// Buffer
	node_buf_t buf;
	char buf_ip[INET6_ADDRSTRLEN];

	// Various
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
	if (server_info_cb) server_info_cb(SERVER_MAIN, sprintf);

	sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_fd == -1) {
		printf("There was a problem creating the socket\n");
	} else if (socket_created_cb) socket_created_cb(sock_fd);

	int br = bind(sock_fd, sa_me_internal, sizeof(*sa_me_internal));
	if ( br == -1 ) pfail("bind");
	if (socket_bound_cb) socket_bound_cb();

	socklen_t gsn_len = sizeof(*sa_me_internal);
	int gsn = getsockname(sock_fd, sa_me_internal, &gsn_len);
	if (gsn == -1) pfail("getsockname");

	addr_to_str_short(sa_me_internal, me_internal_ip, &me_internal_port, &me_internal_family);
	sprintf(sprintf, "Moi %s %s %s", username, me_internal_ip, self_internal_ip);
	if (self_info_cb) self_info_cb(sprintf, me_internal_port, -1, me_internal_family);
	self_internal->port = me_internal_port;

	sendto_len = sendto(sock_fd, self_internal, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);

	// peers = malloc(SZ_LINK_LIST_MN);
	memset(&self, '\0', SZ_HASH_NODE);
	self.nodes = malloc(SZ_LINK_LIST);
	self.contacts = malloc(SZ_CONTACT_LIST);

	size_t max_buf = MAX(size_t, SZ_NODE_BF, SZ_SRCH_BF);
	printf("Start MAIN (%lu)\n", max_buf);
	if (wain_running) wain_thread_has_started = 1;
	while (wain_running) {
		recvf_len = recvfrom(sock_fd, &buf, max_buf, 0, &sa_other, &other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_other, other_ip, other_port, other_family);
		sprintf(sprintf, "WAIN-RCV-FROM %s port%s %s", other_ip, other_port, other_family);
		if (buf.status != STATUS_STAY_IN_TOUCH_RESPONSE && recd_cb)
			recd_cb(SERVER_MAIN, recvf_len, other_socklen, sprintf);
		other_socklen = DEFAULT_OTHER_ADDR_LEN;

		struct sockaddr *buf_sa = NULL;
		node_buf_to_addr(&buf, &buf_sa);
		char bp[20];
		char bf[20];
		addr_to_str(buf_sa, buf_ip, bp, bf);
		sprintf(sprintf, "coll_buf id:%s sz:%zu st:%d ip:%s p:%u CHAT_PORT:%u f:%u",
			buf.id,
			sizeof(buf),
			buf.status,
			buf_ip,
			ntohs(buf.port),
			ntohs(buf.chat_port),
			buf.family);
		if (buf.status != STATUS_STAY_IN_TOUCH_RESPONSE && coll_buf_cb) coll_buf_cb(sprintf);

		if (addr_equals(sa_server, &sa_other)) {
			// The datagram came from the server.
			switch (buf.status) {
				case STATUS_NEW_NODE: {
					self_external = malloc(SZ_NODE_BF);
					memcpy(self_external, &buf, SZ_NODE_BF);
					self_external->chat_port = USHRT_MAX;
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
					if (new_client_cb) new_client_cb(SERVER_MAIN, sprintf);
					stay_in_touch_with_server(SERVER_MAIN);
					init_chat_hp();
					break;
				}
				case STATUS_NOTIFY_EXISTING_CONTACT: {
					add_contact_to_list(self.contacts, buf.id);
					if (notify_existing_contact_cb) notify_existing_contact_cb(buf.id);
					break;
				}
				// TODO add status to populate self->nodes
				case STATUS_STAY_IN_TOUCH_RESPONSE: {
					// if (stay_touch_recd_cb) stay_touch_recd_cb(SERVER_MAIN);
					break;
				}
				case STATUS_DEINIT_NODE: {
					remove_node_from_contact(self.contacts, &buf);
					if (contact_deinit_node_cb) contact_deinit_node_cb(buf.id);
					break;
				}
				case STATUS_REQUEST_ADD_CONTACT_REQUEST: {
					if (add_contact_request_cb) add_contact_request_cb(buf.other_id);
					break;
				}
				case STATUS_REQUEST_ADD_CONTACT_ACCEPT: {
					if (contact_request_accepted_cb) contact_request_accepted_cb(buf.other_id);
					break;
				}
				case STATUS_REQUEST_ADD_CONTACT_DENIED: {
					if (contact_request_declined_cb) contact_request_declined_cb(buf.other_id);
					break;
				}
				case STATUS_CONFIRMED_NODE: {
					if (confirmed_client_cb) confirmed_client_cb();
					break;
				}
				case STATUS_NEW_PEER: {
					// The server code is set to send us a datagram for each peer,
					// in which the payload contains the peer's UDP endpoint data.
					// We're receiving binary data here, sent using the server's
					// byte ordering. We should make sure we agree on the
					// endianness in any serious code.
					// Now we just have to add the reported peer into our peer list
					node_t *new_peer_node;
					add_node_to_contacts(&self, &buf, &new_peer_node);

					if (new_peer_node) {
						sprintf(sprintf, "New peer %s p:%u added\nNow we have %d peers",
							buf_ip,
							ntohs(buf.port),
							self.contacts->count);
					} else {
						sprintf(sprintf, "New peer %s p:%u already exist\nNow we have %d peers",
							buf_ip,
							ntohs(buf.port),
							self.contacts->count);
					}
					if (new_peer_cb) new_peer_cb(sprintf);
                    
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
					punch_hole_in_peer(SERVER_MAIN, new_peer_node);
					break;
                    
				}
				case STATUS_PROCEED_CHAT_HP: {
					node_t *cn;
					lookup_contact_and_node_from_node_buf(self.contacts, &buf, &cn);
					if (cn) {
						// TODO handle ext or int chat_port
						cn->external_chat_port = buf.chat_port;
						punch_hole_in_peer(SERVER_CHAT, cn);
					}
					break;
				}
                    
				default: {
					if (unhandled_response_from_server_cb)
						unhandled_response_from_server_cb(buf.status);
					break;
				}
			}
		} else {
			node_t *existing_node;
			lookup_contact_and_node_from_sockaddr(self.contacts,
				&sa_other, SERVER_MAIN, &existing_node);
			if (!existing_node) {
				/* TODO: This is an issue. Either a security issue (how
				did an unknown peer get through the firewall) or my list
				of peers is wrong. */
				sprintf(sprintf, "FROM UNKNOWN peer: ip:%s port:%s fam:%s",
					other_ip,
					other_port,
					other_family);
				if (from_peer_cb) from_peer_cb(SERVER_MAIN, sprintf);
				continue;
			}

			char conf_stat[40] ;
			switch (existing_node->status) {
				case STATUS_INIT_NODE:
				case STATUS_NEW_NODE:
				case STATUS_STAY_IN_TOUCH:
				case STATUS_STAY_IN_TOUCH_RESPONSE:
				case STATUS_CONFIRMED_NODE:
				case STATUS_NEW_PEER: {
					send_hole_punch(existing_node);
					existing_node->status = STATUS_CONFIRMED_PEER;
					strcpy(conf_stat, "UNCONFIRMED");
					break;
				}
				case STATUS_CONFIRMED_PEER: {
					unsigned short bcp = ntohs(buf.chat_port);
					if (bcp != USHRT_MAX) {
						// TODO handle int_or_ext
						existing_node->external_chat_port = buf.chat_port;
						sprintf(conf_stat, "CONF'D-CHAT-PORT {%d}", ntohs(existing_node->external_chat_port));
						// punch_hole_in_peer(SERVER_CHAT, existing_peer);
					} else {
						strcpy(conf_stat, "CONFIRMED-no-chprt");
						/* TODO This shouldn't happen very often. Both existing_peer
							and self_external should get their chat_port very
							quickly. We could wait to call 
							punch_hole_in_peer(SERVER_SIGNIN, new_peer_added) until receipt of
							chat_port? Or we could create some asynchronous
							process that syncs up receipt of chat_port and hole
							punch. I like the former. It would mean that this
							'else' would never occur, theoretically.
						*/ 
					}
					break;
				}
				case STATUS_CONFIRMED_CHAT_PEER: {
					printf("STATUS_CONFIRMED_CHAT_PEER ping\n");
					break;
				}
				case STATUS_SIGN_OUT: {
					printf("STATUS_SIGN_OUT ping\n");
					break;
				}
				default: {
					sprintf(conf_stat, "Illogical state {%s}", status_to_str(existing_node->status));
					break;
				}
			}

			sprintf(sprintf, "from KNOWN AND %s peer: ip:%s port:%s fam:%s",
				conf_stat,
				other_ip,
				other_port,
				other_family);
			if (from_peer_cb) from_peer_cb(SERVER_MAIN, sprintf);
		}
		free(buf_sa);
	}
	wain_thread_has_started = 0;
	pthread_exit("wain_thread exited normally");
}

int wain(void (*self_info)(char *, unsigned short, unsigned short, unsigned short),
	void (*server_info)(SERVER_TYPE, char *),
	void (*socket_created)(int),
	void (*socket_bound)(void),
	void (*sendto_succeeded)(size_t),
	void (*coll_buf)(char *),
	void (*new_client)(SERVER_TYPE, char *),
	void (*confirmed_client)(void),
	void (*notify_existing_contact)(char *),
	void (*stay_touch_recd)(SERVER_TYPE),
	void (*contact_deinit_node)(char *),
	void (*add_contact_request)(char *),
	void (*contact_request_accepted)(char *),
	void (*contact_request_declined)(char *),
	void (*new_peer)(char *),
	void (*hole_punch_sent)(char *, int),
	void (*confirmed_peer_while_punching)(SERVER_TYPE),
	void (*from_peer)(SERVER_TYPE, char *),
	void (*chat_msg)(char *),
	void (*unhandled_response_from_server)(int),
	void (*whilew)(int),
	void (*end_while)(void)) {

	printf("main 0 %lu\n", DEFAULT_OTHER_ADDR_LEN);
	self_info_cb = self_info;
	server_info_cb = server_info;
	socket_created_cb = socket_created;
	socket_bound_cb = socket_bound;
	sendto_succeeded_cb = sendto_succeeded;
	notify_existing_contact_cb = notify_existing_contact;
	stay_touch_recd_cb = stay_touch_recd;
	coll_buf_cb = coll_buf;
	new_client_cb = new_client;
	confirmed_client_cb = confirmed_client;
	hole_punch_sent_cb = hole_punch_sent;
	contact_deinit_node_cb = contact_deinit_node;
	add_contact_request_cb = add_contact_request;
	contact_request_accepted_cb = contact_request_accepted;
	contact_request_declined_cb = contact_request_declined;
	new_peer_cb = new_peer;
	confirmed_peer_while_punching_cb = confirmed_peer_while_punching;
	from_peer_cb = from_peer;
	chat_msg_cb = chat_msg;
	unhandled_response_from_server_cb = unhandled_response_from_server;

	int wtr = pthread_create(&wain_thread, NULL, wain_thread_routine, "wain_thread");
	if (wtr) {
		printf("ERROR in wain_thread creation; return code from pthread_create() is %d\n", wtr);
		return -1;
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
	chat_server_socklen = sa_chat_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	addr_to_str(sa_chat_server, server_internal_ip, server_internal_port, server_internal_family);
	sprintf(sprintf, "The chat server %s port%s %s %u",
		server_internal_ip,
		server_internal_port,
		server_internal_family,
		chat_server_socklen);
	if (server_info_cb) server_info_cb(SERVER_CHAT, sprintf);

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
	char buf_ip[INET6_ADDRSTRLEN];

	size_t chat_sendto_len = sendto(chat_sock_fd, &buf, sizeof(node_t), 0, sa_chat_server, chat_server_socklen);
	if (chat_sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", chat_sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(chat_sendto_len);

	chat_server_conn_running = 1;
	while (chat_server_conn_running) {

		size_t recvf_len = recvfrom(chat_sock_fd, &buf, SZ_CH_BF, 0, &sa_chat_other, &chat_other_socklen);
		if (recvf_len == -1) {
			char w[256];
			sprintf(w, "recvfrom failed with %zu", recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_chat_other, chat_other_ip, chat_other_port, chat_other_family);
		sprintf(sprintf, "CHAT-RECV-FRM %s port%s %s", chat_other_ip, chat_other_port, chat_other_family);
		if (buf.status != CHAT_STATUS_STAY_IN_TOUCH_RESPONSE && recd_cb)
			recd_cb(SERVER_CHAT, recvf_len, chat_other_socklen, sprintf);
		chat_other_socklen = DEFAULT_OTHER_ADDR_LEN;

		struct sockaddr *buf_sa = NULL;
		chatbuf_to_addr(&buf, &buf_sa);
		char bp[20];
		char bf[20];
		addr_to_str(buf_sa, buf_ip, bp, bf);
		sprintf(sprintf, "coll_buf sz:%zu st:%d ip:%s cp:%u f:%u",
			sizeof(buf),
			buf.status,
			buf_ip,
			ntohs(buf.port),
			buf.family);
		if (buf.status != CHAT_STATUS_STAY_IN_TOUCH_RESPONSE && coll_buf_cb) coll_buf_cb(sprintf);

		if (addr_equals(sa_chat_server, &sa_chat_other)) {

			switch (buf.status) {
				case CHAT_STATUS_NEW: {
					self_external->chat_port = buf.port;
					self_external->status = STATUS_ACQUIRED_CHAT_PORT;
					memcpy(self_external->authn_token, authentication_token, AUTHEN_TOKEN_LEN);
					size_t stl = sendto(sock_fd, self_external, SZ_NODE_BF, 0, sa_server, server_socklen);
					if (stl == -1) {
						char w[256];
						sprintf(w, "sendto failed with %zu", stl);
						pfail(w);
					}
					// TODO make function ip4 and port to str
					sprintf(sprintf, "Chat Moi aussie chat_port(%d)", ntohs(buf.port));
					if (new_client_cb) new_client_cb(SERVER_CHAT, sprintf);
					stay_in_touch_with_server(SERVER_CHAT);
					break;
				}
				case CHAT_STATUS_STAY_IN_TOUCH_RESPONSE: {
					// if (stay_touch_recd_cb) stay_touch_recd_cb(SERVER_CHAT);
					break;
				}
				default: printf("&-&-&-&-&-&-&-&-&-&-&-& chat server\n");
			}
		} else {
			// TODO only set n->status = STATUS_CONFIRMED_CHAT_PEER
			// for the recd peer
			// node_min_t *n = peers->head;
			// while (n) {
			// 	n->status = STATUS_CONFIRMED_CHAT_PEER;
			// 	n = n->next;
			// }

			node_t *existing_node;
			lookup_contact_and_node_from_sockaddr(self.contacts,
				&sa_chat_other, SERVER_CHAT, &existing_node);
			if (!existing_node) {
				/* TODO: This is an issue. Either a security issue (how
				did an unknown peer get through the firewall) or my list
				of peers is wrong. */
				sprintf(sprintf, "CHAT FROM UNKNOWN peer: ip:%s port:%s fam:%s",
					chat_other_ip,
					chat_other_port,
					chat_other_family);
				if (from_peer_cb) from_peer_cb(SERVER_CHAT, sprintf);
				continue;
			}

			char conf_stat[40];
			switch (buf.status) {
				case CHAT_STATUS_INIT:
				case CHAT_STATUS_NEW:
				case CHAT_STATUS_STAY_IN_TOUCH:
				case CHAT_STATUS_STAY_IN_TOUCH_RESPONSE: {
					sprintf(conf_stat, "%s", chat_status_to_str(buf.status));
					break;
				}
				case CHAT_STATUS_ATTEMPTING_HOLE_PUNCH: {
					existing_node->status = STATUS_CONFIRMED_CHAT_PEER;
					sprintf(conf_stat, "%s", chat_status_to_str(buf.status));
					break;
				}
				case CHAT_STATUS_MSG: {
					if (chat_msg_cb) chat_msg_cb(buf.msg);
					sprintf(conf_stat, "%s", chat_status_to_str(buf.status));
					break;
				}

			}

			sprintf(sprintf, "#-#-#-#-#-#-#-#-\nfrom %s peer: ip:%s chat_port:%s fam:%s",
				conf_stat,
				chat_other_ip,
				chat_other_port,
				chat_other_family);
			if (from_peer_cb) from_peer_cb(SERVER_CHAT, sprintf);
		}

	}

	pthread_exit("chat_hp_server exiting normally");
}

void *chat_hole_punch_thread(void *peer_to_hole_punch) {
	node_t *peer = (node_t *)peer_to_hole_punch;
	for (int j = 0; j < HOLE_PUNCH_RETRY_ATTEMPTS; j++) {
		// Send (HOLE_PUNCH_RETRY_ATTEMPTS) datagrams, or until the peer
		// is confirmed, whichever occurs first.
		if (peer->status >= STATUS_CONFIRMED_CHAT_PEER) {
			if (confirmed_peer_while_punching_cb)
				confirmed_peer_while_punching_cb(SERVER_CHAT);
			break;
		}
		send_chat_hole_punch(peer);
		usleep(MICROSECONDS_TO_WAIT_BTWN_HOLE_PUNCH_ATTEMPTS);
	}
	pthread_exit("hole_punch_thread exiting normally");
}

void send_chat_hole_punch(node_t *peer) {
	if (!peer) return;
	// TODO set peer->status = STATUS_NEW_PEER?
	// and then set back to previous status?
	static int chpc = 0;
	struct sockaddr *peer_addr;
	socklen_t peer_socklen = 0;
	// TODO handle int_or_ext
	switch (peer->external_family) {
		case AF_INET: {
			struct sockaddr_in sa4;
			sa4.sin_family = AF_INET;
			sa4.sin_addr.s_addr = peer->external_ip4;
			sa4.sin_port = peer->external_chat_port;
			peer_socklen = SZ_SOCKADDR_IN;
			peer_addr = (struct sockaddr*)&sa4;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 sa6;
			sa6.sin6_family = AF_INET6;
			memcpy(sa6.sin6_addr.s6_addr, peer->external_ip6, sizeof(unsigned char[16]));
			sa6.sin6_port = peer->external_chat_port;
			peer_socklen = SZ_SOCKADDR_IN6;
			peer_addr = (struct sockaddr*)&sa6;
			break;
		}
		default: {
			printf("send_chat_hole_punch, peer->family not well defined\n");
			return;
		}
	}
	chat_buf_t wcb;
	wcb.status = CHAT_STATUS_ATTEMPTING_HOLE_PUNCH;
	wcb.family = self_external->family;
	wcb.port = self_external->chat_port;
	wcb.ip4 = self_external->ip4;

	if (sendto(chat_sock_fd, &wcb, SZ_CH_BF, 0, peer_addr, peer_socklen) == -1)
		pfail("send_chat_hole_punch sendto");
	char spf[256];
	char pi[INET6_ADDRSTRLEN];
	char pp[20];
	char pf[20];
	addr_to_str(peer_addr, pi, pp, pf);
	sprintf(spf, "send_chat_hole_punchXXX %s %s %s\n", pi, pp, pf);
	if (hole_punch_sent_cb) hole_punch_sent_cb(spf, ++chpc);
}

void *search_thread_routine(void *arg) {
	printf("search_thread_routine %s\n", (char *)arg);
	char wayne[256];

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

	// Setup search server
	char search_port[10];
	sprintf(search_port, "%d", SEARCH_PORT);
	str_to_addr(&sa_search_server, "142.105.56.124", search_port, AF_INET, SOCK_DGRAM, 0);
	search_server_socklen = sa_search_server->sa_family == AF_INET6 ? SZ_SOCKADDR_IN6 : SZ_SOCKADDR_IN;
	addr_to_str(sa_search_server, server_internal_ip, server_internal_port, server_internal_family);
	sprintf(wayne, "The search server %s port%s %s %u",
		server_internal_ip,
		server_internal_port,
		server_internal_family,
		search_server_socklen);
	if (server_info_cb) server_info_cb(SERVER_SEARCH, wayne);

	// Setup sa_search_other
	struct sockaddr sa_search_other;
	char search_other_ip[INET6_ADDRSTRLEN];
	char search_other_port[20];
	char search_other_family[20];
	socklen_t search_other_socklen = DEFAULT_OTHER_ADDR_LEN;

	search_sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (search_sock_fd == -1) {
		printf("There was a problem creating the socket\n");
	} else if (socket_created_cb) socket_created_cb(search_sock_fd);

	search_buf_t buf;
	memset(&buf, '\0', SZ_SRCH_BF);
	char buf_ip[INET6_ADDRSTRLEN];

	if (search_running) search_thread_has_started = 1;
	else search_thread_has_started = 0;
	while (search_running) {
		search_recvf_len = recvfrom(search_sock_fd, &buf, SZ_SRCH_BF, 0, &sa_search_other, &search_other_socklen);
		if (search_recvf_len == -1) {
			char w[256];
			sprintf(w, "search recvfrom failed with %zu", search_recvf_len);
			pfail(w);
		}

		addr_to_str(&sa_search_other, search_other_ip, search_other_port, search_other_family);
		sprintf(wayne, "(%s) %s port%s %s", search_status_to_str(buf.status),
			search_other_ip, search_other_port, search_other_family);
		if (recd_cb) recd_cb(SERVER_SEARCH, search_recvf_len, search_other_socklen, wayne);
		search_other_socklen = DEFAULT_OTHER_ADDR_LEN;

		switch (buf.status) {
			case SEARCH_STATUS_USERNAME_RESPONSE: {
				if (username_results_cb)
					username_results_cb(buf.search_results, buf.number_of_search_results);
				break;
			}
			case SEARCH_STATUS_USERNAME: {
				printf("SEARCH_STATUS_USERNAME This should never occur\n");
				break;
			}
		}
	}
	search_thread_has_started = 0;
	pthread_exit("search_thread_routine exited normally");
}

int search_start() {
	search_running = 1;
	int stc = pthread_create(&search_thread, NULL, search_thread_routine, "");
	if (stc) {
		printf("ERROR in search_thread creation; return code from pthread_create() is %d\n", stc);
		return -1;
	}
	return 0;
}

void search_username(const char *searchname,
	void (*username_results)(char search_results[MAX_SEARCH_RESULTS][MAX_CHARS_USERNAME], int number_of_search_results)) {

	while (!search_thread_has_started) {
		search_start();
		usleep(10*1000); // 10 milliseconds
	}
	username_results_cb = username_results;
	search_buf_t buf;
	memset(&buf, '\0', SZ_SRCH_BF);
	buf.status = SEARCH_STATUS_USERNAME;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	memcpy(buf.search_text, searchname, MAX_CHARS_USERNAME);
	switch (sa_me_external->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in*)sa_me_external;
			buf.main_port = sa4->sin_port;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)sa_me_external;
			buf.main_port = sa6->sin6_port;
			break;
		}
		default: {
			return;
		}
	}
	size_t sendto_len = sendto(search_sock_fd, &buf, SZ_SRCH_BF, 0, sa_search_server, search_server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);
}

void send_message_to_all_nodes_in_contact(contact_t *contact, void *msg, void *arg2_unused, void *arg3_unused) {
	if (!contact || !contact->hn || !contact->hn->nodes) return;
	nodes_perform(contact->hn->nodes, send_message_to_peer, msg, NULL, NULL, NULL);
}

void send_message_to_contact(contact_t *c, char *msg) {
	send_message_to_all_nodes_in_contact(c, msg, NULL, NULL);
}

void send_message_to_all_peers(char *msg) {
	if (!self.contacts) return;
	contacts_perform(self.contacts, send_message_to_all_nodes_in_contact, msg, NULL, NULL);
}

void send_message_to_peer(node_t *peer, void *msg, void *arg2_unused, void *arg3_unused, void *arg4_unused) {
	if (!peer) return;
	struct sockaddr *peer_addr;
	socklen_t peer_socklen = 0;
	// TODO handle int_or_ext
	switch (peer->external_family) {
		case AF_INET: {
			struct sockaddr_in sa4;
			sa4.sin_family = AF_INET;
			sa4.sin_addr.s_addr = peer->external_ip4;
			sa4.sin_port = peer->external_chat_port;
			peer_socklen = SZ_SOCKADDR_IN;
			peer_addr = (struct sockaddr*)&sa4;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 sa6;
			sa6.sin6_family = AF_INET6;
			memcpy(sa6.sin6_addr.s6_addr, peer->external_ip6, sizeof(unsigned char[16]));
			sa6.sin6_port = peer->external_chat_port;
			peer_socklen = SZ_SOCKADDR_IN6;
			peer_addr = (struct sockaddr*)&sa6;
			break;
		}
		default: {
			printf("send_message_to_peer, peer->family not well defined\n");
			return;
		}
	}
	chat_buf_t wcb;
	wcb.status = CHAT_STATUS_MSG;
	wcb.family = self_external->family;
	wcb.port = self_external->chat_port;
	wcb.ip4 = self_external->ip4;
	strcpy(wcb.msg, msg);

	if (sendto(chat_sock_fd, &wcb, SZ_CH_BF, 0, peer_addr, peer_socklen) == -1)
		pfail("send_message_to_peer sendto");
}

void list_contacts(contact_list_t **contacts) {
	if (!contacts) return;
	*contacts = self.contacts;
}

void client_request_to_add_contact(char *contact_username) {
	node_buf_t buf = {0};
	buf.status = STATUS_REQUEST_ADD_CONTACT_REQUEST;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	strcpy(buf.other_id, contact_username);
	size_t sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);	
}

void accept_contact_request(char *contact_username) {
	node_buf_t buf = {0};
	buf.status = STATUS_REQUEST_ADD_CONTACT_ACCEPT;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	strcpy(buf.other_id, contact_username);
	size_t sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);
}

void decline_contact_request(char *contact_username) {
	node_buf_t buf = {0};
	buf.status = STATUS_REQUEST_ADD_CONTACT_DENIED;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	strcpy(buf.other_id, contact_username);
	size_t sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);
}

void quit() {
	node_buf_t buf = {0};
	buf.status = STATUS_DEINIT_NODE;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	size_t sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);
}

void signout() {
	node_buf_t buf;
	memset(&buf, '\0', SZ_NODE_BF);
	buf.status = STATUS_SIGN_OUT;
	strcpy(buf.id, username);
	memcpy(buf.authn_token, authentication_token, AUTHEN_TOKEN_LEN);
	size_t sendto_len = sendto(sock_fd, &buf, SZ_NODE_BF, 0, sa_server, server_socklen);
	if (sendto_len == -1) {
		char w[256];
		sprintf(w, "sendto failed with %zu", sendto_len);
		pfail(w);
	} else if (sendto_succeeded_cb) sendto_succeeded_cb(sendto_len);

	wain_running = 0;
	authn_running = 0;
	stay_in_touch_running = 0;
	chat_stay_in_touch_running = 0;
	chat_server_conn_running = 0;
}
