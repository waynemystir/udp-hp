//
//  common.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef common_h
#define common_h

#include <netdb.h>

#define MAX_CHARS_USERNAME 47
#define MAX_CHARS_PASSWORD 28
#define RSA_PUBLIC_KEY_LEN 512
#define NUM_BITS_AES_KEY 256
#define NUM_BITS_IV_KEY 128
#define NUM_BYTES_AES_KEY NUM_BITS_AES_KEY/8
#define NUM_BYTES_AES_IV NUM_BITS_IV_KEY/8
#define NUM_BYTES_RSA_ENCRYPTED_DATA 256
#define AUTHEN_TOKEN_LEN 160
#define AUTHN_HASHSIZE 10001
#define AUTHN_NODE_KEY_LENGTH INET6_ADDRSTRLEN + 20 + 20
#define AES_PADDING 16

typedef enum SERVER_TYPE {
	SERVER_AUTHN,
	SERVER_MAIN,
	SERVER_CHAT,
} SERVER_TYPE;

typedef enum AUTHN_STATUS {
	AUTHN_STATUS_ENCRYPTED = 0,
	AUTHN_STATUS_RSA_SWAP = 1,
	AUTHN_STATUS_RSA_SWAP_RESPONSE = 2,
	AUTHN_STATUS_AES_SWAP = 3,
	AUTHN_STATUS_AES_SWAP_RESPONSE = 4,
	AUTHN_STATUS_NEW_USER = 5,
	AUTHN_STATUS_NEW_USER_RESPONSE = 6, // we return the AuthN token here
	// TODO I think we can handle existing user from BOTH new or existing device
	// with AUTHN_STATUS_EXISTING_USER, right? We don't need to treat existing
	// user differently whether they are using new or existing device, yeah?
	AUTHN_STATUS_EXISTING_USER = 7,
	AUTHN_STATUS_EXISTING_USER_RESPONSE = 8, // we return the AuthN token here
	AUTHN_STATUS_SIGN_OUT = 9,
} AUTHN_STATUS;

typedef struct authn_buf {
	AUTHN_STATUS status;
	union {
		unsigned char rsa_pub_key[RSA_PUBLIC_KEY_LEN];
		unsigned char aes_key[NUM_BYTES_RSA_ENCRYPTED_DATA];
		unsigned char auth_token[AUTHEN_TOKEN_LEN];
	};
	unsigned char aes_iv[NUM_BYTES_AES_IV];
	char id[MAX_CHARS_USERNAME];
	char pw[MAX_CHARS_PASSWORD];
} authn_buf_t;

typedef struct authn_node {
	AUTHN_STATUS status;
	char key[AUTHN_NODE_KEY_LENGTH];
	unsigned char rsa_pub_key[RSA_PUBLIC_KEY_LEN];
	unsigned char aes_key[NUM_BYTES_AES_KEY];
	unsigned char aes_iv[NUM_BYTES_AES_IV];
	unsigned char auth_token[AUTHEN_TOKEN_LEN];
	char id[MAX_CHARS_USERNAME];
	char pw[MAX_CHARS_PASSWORD];
	struct authn_node *next;
} authn_node_t;

typedef authn_node_t *authn_hashtable_t[AUTHN_HASHSIZE];

typedef enum CHAT_STATUS {
	CHAT_STATUS_INIT = 0,
	CHAT_STATUS_NEW = 1,
	CHAT_STATUS_STAY_IN_TOUCH = 2,
	CHAT_STATUS_STAY_IN_TOUCH_RESPONSE = 3,
	CHAT_STATUS_ATTEMPTING_HOLE_PUNCH = 4,
	CHAT_STATUS_MSG = 5,
} CHAT_STATUS;

typedef struct chat_buf {
	CHAT_STATUS status;
	union {
		in_addr_t ip4;
		unsigned char ip6[16];
	};
	in_port_t port;
	sa_family_t family;
	char msg[64];
} chat_buf_t;

extern const unsigned short AUTHENTICATION_PORT;

char *authn_status_to_str(AUTHN_STATUS as);
char *str_from_server_type(SERVER_TYPE st);
char *chat_status_to_str(CHAT_STATUS cs);

char *authn_addr_info_to_key(sa_family_t family, char *ip_str, in_port_t port);
authn_node_t *add_authn_node(authn_hashtable_t *ahtbl, AUTHN_STATUS status, char *key);
authn_node_t *lookup_authn_node(authn_hashtable_t *ahtbl, char *key);

int chatbuf_to_addr(chat_buf_t *cb, struct sockaddr **addr);

#define SZ_AUN_BF sizeof(authn_buf_t)
#define SZ_CH_BF sizeof(chat_buf_t)
#define SZ_AUN_ND sizeof(authn_node_t)
#define SZ_AUN_TBL sizeof(authn_hashtable_t)

typedef struct authn_buf_encrypted {
	AUTHN_STATUS status;
	unsigned char encrypted_buf[SZ_AUN_BF + AES_PADDING];
	int encrypted_len;
} authn_buf_encrypted_t;

#define SZ_AE_BUF sizeof(authn_buf_encrypted_t)

#endif /* common_h */
