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
#define MAX_CHARS_PASSWORD 20
#define RSA_PUBLIC_KEY_LEN 512
#define NUM_BYTES_AES_KEY 256
#define NUM_BYTES_AES_IV 128
#define AUTHEN_TOKEN_LEN 160

typedef enum SERVER_TYPE {
	SERVER_AUTHN,
	SERVER_MAIN,
	SERVER_CHAT,
} SERVER_TYPE;

typedef enum AUTHN_STATUS {
	AUTHN_STATUS_RSA_SWAP = 0,
	AUTHN_STATUS_RSA_SWAP_RESPONSE = 1,
	AUTHN_STATUS_AES_SWAP = 2,
	AUTHN_STATUS_AES_SWAP_RESPONSE = 3,
	AUTHN_STATUS_NEW_USER = 4,
	AUTHN_STATUS_NEW_USER_RESPONSE = 5,
	AUTHN_STATUS_AUTH_TOKEN = 6,
	AUTHN_STATUS_AUTH_TOKEN_RESPONSE = 7,
	AUTHN_STATUS_SIGN_OUT = 8,
} AUTHN_STATUS;

typedef struct authn_buf {
	AUTHN_STATUS status;
	union {
		unsigned char rsa_pub_key[RSA_PUBLIC_KEY_LEN];
		unsigned char aes_key[NUM_BYTES_AES_KEY];
		unsigned char auth_token[AUTHEN_TOKEN_LEN];
	};
	char id[MAX_CHARS_USERNAME];
	char pw[MAX_CHARS_PASSWORD];
} authn_buf_t;

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

int chatbuf_to_addr(chat_buf_t *cb, struct sockaddr **addr);

#define SZ_AUN_BF sizeof(authn_buf_t)
#define SZ_CH_BF sizeof(chat_buf_t)

#endif /* common_h */
