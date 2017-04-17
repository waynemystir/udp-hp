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

#define MAX_CONNECTIONS 5
#define MAX_CHARS_USERNAME 32
#define MAX_CHARS_PASSWORD 28
#define MAX_CHARS_SEARCH 24
#define MAX_SEARCH_RESULTS 20
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
#define NUMBER_SECOND_BTWN_STAY_IN_TOUCH 3
#define HOLE_PUNCH_RETRY_ATTEMPTS 200
#define MICROSECONDS_TO_WAIT_BTWN_HOLE_PUNCH_ATTEMPTS 30 * 1000
#define AUTHN_RETRY_ATTEMPTS 100
#define MICROSECONDS_TO_WAIT_BTWN_AUTHN_ATTEMPTS 10 * 1000
#define VIDEO_SERVER_HOST_URL "https://appr.tc"

extern const char USERNAME_ALLOWED_CHARS[65];

typedef enum SERVER_TYPE {
	SERVER_AUTHN,
	SERVER_SEARCH,
	SERVER_MAIN,
	SERVER_CHAT,
} SERVER_TYPE;

typedef enum NODE_USER_STATUS {
	NODE_USER_STATUS_NEW_USER = 0,
	NODE_USER_STATUS_EXISTING_USER = 1,
	NODE_USER_STATUS_UNKNOWN = 2,
} NODE_USER_STATUS;

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
	AUTHN_STATUS_CREDS_CHECK_RESULT = 9,
	AUTHN_STATUS_SIGN_OUT = 10,
} AUTHN_STATUS;

typedef enum AUTHN_CREDS_CHECK_RESULT {
	AUTHN_CREDS_CHECK_RESULT_GOOD = 0,
	AUTHN_CREDS_CHECK_RESULT_USER_NOT_FOUND = 1,
	AUTHN_CREDS_CHECK_RESULT_WRONG_PASSWORD = 2,
	AUTHN_CREDS_CHECK_RESULT_USERNAME_ALREADY_EXISTS = 3,
	AUTHN_CREDS_CHECK_RESULT_MISC_ERROR = 4,
} AUTHN_CREDS_CHECK_RESULT;

typedef struct authn_buf {
	AUTHN_STATUS status;
	union {
		unsigned char rsa_pub_key[RSA_PUBLIC_KEY_LEN];
		unsigned char aes_key[NUM_BYTES_RSA_ENCRYPTED_DATA];
		unsigned char authn_token[AUTHEN_TOKEN_LEN];
	};
	unsigned char aes_iv[NUM_BYTES_AES_IV];
	char id[MAX_CHARS_USERNAME];
	char pw[MAX_CHARS_PASSWORD];
	AUTHN_CREDS_CHECK_RESULT authn_result;
} authn_buf_t;

typedef struct authn_node {
	AUTHN_STATUS status;
	char key[AUTHN_NODE_KEY_LENGTH];
	unsigned char rsa_pub_key[RSA_PUBLIC_KEY_LEN];
	unsigned char aes_key[NUM_BYTES_AES_KEY];
	unsigned char aes_iv[NUM_BYTES_AES_IV];
	unsigned char authn_token[AUTHEN_TOKEN_LEN];
	char id[MAX_CHARS_USERNAME];
	char pw[MAX_CHARS_PASSWORD];
	struct authn_node *next;
} authn_node_t;

typedef authn_node_t *authn_hashtable_t[AUTHN_HASHSIZE];

typedef struct token_node {
	unsigned char authn_token[AUTHEN_TOKEN_LEN];
	struct token_node *next;
} token_node_t;

typedef token_node_t *token_hashtable_t[AUTHN_HASHSIZE];

typedef enum CHAT_STATUS {
	CHAT_STATUS_INIT = 0,
	CHAT_STATUS_NEW = 1,
	CHAT_STATUS_STAY_IN_TOUCH = 2,
	CHAT_STATUS_STAY_IN_TOUCH_RESPONSE = 3,
	CHAT_STATUS_ATTEMPTING_HOLE_PUNCH = 4,
	CHAT_STATUS_MSG = 5,
	CHAT_STATUS_VIDEO_START = 6,
} CHAT_STATUS;

typedef struct chat_buf {
	CHAT_STATUS status;
	char id[MAX_CHARS_USERNAME];
	union {
		in_addr_t ip4;
		unsigned char ip6[16];
	};
	in_port_t port;
	sa_family_t family;
	char msg[64];
} chat_buf_t;

extern const unsigned short AUTHENTICATION_PORT;
extern const unsigned short SEARCH_PORT;

char *authn_status_to_str(AUTHN_STATUS as);
char *creds_check_result_to_str(AUTHN_CREDS_CHECK_RESULT r);
char *str_from_server_type(SERVER_TYPE st);
char *chat_status_to_str(CHAT_STATUS cs);
char *node_user_status_to_str(NODE_USER_STATUS nus);

char *authn_addr_info_to_key(sa_family_t family, char *ip_str, in_port_t port);
authn_node_t *add_authn_node(authn_hashtable_t *ahtbl, AUTHN_STATUS status, char *key);
authn_node_t *lookup_authn_node(authn_hashtable_t *ahtbl, char *key);
void remove_authn_node(authn_hashtable_t *ahtbl, char *key);

token_node_t *add_token_node(token_hashtable_t *thtbl, unsigned char *authn_token);
token_node_t *lookup_token_node(token_hashtable_t *thtbl, unsigned char *authn_token);
void remove_token_node(token_hashtable_t *thtbl, unsigned char *authn_token);

int chatbuf_to_addr(chat_buf_t *cb, struct sockaddr **addr);

#define SZ_AUN_BF sizeof(authn_buf_t)
#define SZ_CH_BF sizeof(chat_buf_t)
#define SZ_AUN_ND sizeof(authn_node_t)
#define SZ_AUN_TBL sizeof(authn_hashtable_t)
#define SZ_TKN_ND sizeof(token_node_t)

#define GENERIC_MAX(x, y) ((x) > (y) ? (x) : (y))

#define ENSURE_int(i)   _Generic((i), int:   (i))
#define ENSURE_float(f) _Generic((f), float: (f))
#define ENSURE_size_t(s) _Generic((s), size_t: (s))

#define MAX(type, x, y) \
  (type)GENERIC_MAX(ENSURE_##type(x), ENSURE_##type(y))

typedef struct authn_buf_encrypted {
	AUTHN_STATUS status;
	unsigned char encrypted_buf[SZ_AUN_BF + AES_PADDING];
	int encrypted_len;
} authn_buf_encrypted_t;

#define SZ_AE_BUF sizeof(authn_buf_encrypted_t)

unsigned int calc_triangular_numbr(unsigned int x);

void get_all_substrings(char *str, char **sub_strs, unsigned int *numb_sub_strs, unsigned int *max_len);

void get_substrings_from_beginning(char *str, char **sub_strs, unsigned int *numb_sub_strs, unsigned int *max_len);

#endif /* common_h */
