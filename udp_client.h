//
//  udp_client.h
//  udp-hole-punch
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef udp_client_h
#define udp_client_h

#include "common.h"
#include "hashtable.h"
#include "network_utils.h"

int authn(NODE_USER_STATUS user_stat,
	const char *usernm,
	const char *passwd,
	AUTHN_STATUS auth_status,
	const char *rsa_pub_key,
	const char *rsa_pri_key,
	unsigned char *aes_key,
	void (*rsakeypair_generated)(const char *rsa_pub_key, const char *rsa_pri_key),
	void (*recd)(SERVER_TYPE, size_t, socklen_t, char *),
	void (*rsa_response)(char *server_rsa_pub_key),
	void (*aes_key_created)(unsigned char[NUM_BYTES_AES_KEY]),
	void (*creds_check_result)(AUTHN_CREDS_CHECK_RESULT, char *username,
		char *password, unsigned char[AUTHEN_TOKEN_LEN]));

int send_user(NODE_USER_STATUS nus, char *usernm, char *pw);

int wain(void (*self_info)(char *, unsigned short port, unsigned short chat_port, unsigned short family),
	void (*server_info_cb)(SERVER_TYPE, char *),
	void (*socket_created)(int sock_fd),
	void (*socket_bound)(void),
	void (*sendto_succeeded)(size_t bytes_sent),
	void (*coll_buf)(char *),
	void (*new_client)(SERVER_TYPE, char *),
	void (*confirmed_client)(void),
	void (*notify_existing_contact)(char *),
	void (*stay_touch_recd)(SERVER_TYPE),
	void (*new_peer)(char *),
	void (*hole_punch_sent)(char *, int),
	void (*confirmed_peer_while_punching)(SERVER_TYPE),
	void (*from_peer)(SERVER_TYPE, char *),
	void (*chat_msg)(char *),
	void (*unhandled_response_from_server)(int),
	void (*whilew)(int),
	void (*end_while)(void));

void search_username(const char *searchname,
	void(*username_results)(char search_results[MAX_SEARCH_RESULTS][MAX_CHARS_USERNAME], int number_of_search_results));

void ping_all_peers();

void send_message_to_contact(contact_t *c, char *msg);

void send_message_to_all_peers(char *);

void send_message_to_peer(node_t *peer, void *msg, void *arg2_unused, void *arg3_unused);

void list_contacts(contact_list_t **contacts);

void signout();

#endif /* udp_client_h */
