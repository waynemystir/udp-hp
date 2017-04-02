#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

const unsigned short AUTHENTICATION_PORT = 9929;

char *authn_status_to_str(AUTHN_STATUS as) {
	switch (as) {
		case AUTHN_STATUS_ENCRYPTED: return "AUTHN_STATUS_ENCRYPTED";
		case AUTHN_STATUS_RSA_SWAP: return "AUTHN_STATUS_RSA_SWAP";
		case AUTHN_STATUS_RSA_SWAP_RESPONSE: return "AUTHN_STATUS_RSA_SWAP_RESPONSE";
		case AUTHN_STATUS_AES_SWAP: return "AUTHN_STATUS_AES_SWAP";
		case AUTHN_STATUS_AES_SWAP_RESPONSE: return "AUTHN_STATUS_AES_SWAP_RESPONSE";
		case AUTHN_STATUS_NEW_USER: return "AUTHN_STATUS_NEW_USER";
		case AUTHN_STATUS_NEW_USER_RESPONSE: return "AUTHN_STATUS_NEW_USER_RESPONSE";
		case AUTHN_STATUS_EXISTING_USER: return "AUTHN_STATUS_EXISTING_USER";
		case AUTHN_STATUS_EXISTING_USER_RESPONSE: return "AUTHN_STATUS_EXISTING_USER_RESPONSE";
		case AUTHN_STATUS_CREDS_CHECK_RESULT: return "AUTHN_STATUS_CREDS_CHECK_RESULT";
		case AUTHN_STATUS_SIGN_OUT: return "AUTHN_STATUS_SIGN_OUT";
		default: return "AUTHN_STATUS_UNKNOWN";
	}
}

char *creds_check_result_to_str(AUTHN_CREDS_CHECK_RESULT r) {
	switch (r) {
		case AUTHN_CREDS_CHECK_RESULT_GOOD: return "AUTHN_CREDS_CHECK_RESULT_GOOD";
		case AUTHN_CREDS_CHECK_RESULT_USER_NOT_FOUND: return "AUTHN_CREDS_CHECK_RESULT_USER_NOT_FOUND";
		case AUTHN_CREDS_CHECK_RESULT_WRONG_PASSWORD: return "AUTHN_CREDS_CHECK_RESULT_WRONG_PASSWORD";	
		case AUTHN_CREDS_CHECK_RESULT_MISC_ERROR: return "AUTHN_CREDS_CHECK_RESULT_MISC_ERROR";
		default: return "AUTHN_CREDS_CHECK_UNKNOWN";
	}
}

char *str_from_server_type(SERVER_TYPE st) {
	switch (st) {
		case SERVER_AUTHN: return "SERVER_AUTHN";
		case SERVER_MAIN: return "SERVER_MAIN";
		case SERVER_CHAT: return "SERVER_CHAT";
		default: return "SERVER_UNKNOWN";
	}
}

char *chat_status_to_str(CHAT_STATUS cs) {
	switch (cs) {
		case CHAT_STATUS_INIT: return "CHAT_STATUS_INIT";
		case CHAT_STATUS_NEW: return "CHAT_STATUS_NEW";
		case CHAT_STATUS_STAY_IN_TOUCH: return "CHAT_STATUS_STAY_IN_TOUCH";
		case CHAT_STATUS_STAY_IN_TOUCH_RESPONSE: return "CHAT_STATUS_STAY_IN_TOUCH_RESPONSE";
		case CHAT_STATUS_ATTEMPTING_HOLE_PUNCH: return "CHAT_STATUS_ATTEMPTING_HOLE_PUNCH";
		case CHAT_STATUS_MSG: return "CHAT_STATUS_MSG";
		default: return "CHAT_STATUS_UNKNOWN";
	}
}

char *authn_addr_info_to_key(sa_family_t family, char *ip_str, in_port_t port) {

	char *wes = malloc(AUTHN_NODE_KEY_LENGTH);
	memset(wes, '\0', AUTHN_NODE_KEY_LENGTH);

	switch (family) {
		case AF_INET: {
			strcat(wes, "AF_INET");
			break;
		}
		case AF_INET6: {
			strcat(wes, "AF_INET6");
			break;
		}
		default: return NULL;
	}

	if (strlen(wes) + strlen(ip_str) >= AUTHN_NODE_KEY_LENGTH) {
		int substr_len = AUTHN_NODE_KEY_LENGTH - strlen(wes);
		char subbuff[substr_len];
		memcpy(subbuff, ip_str, substr_len);
	} else {
		strcat(wes, ip_str);
	}
	char port_str[20];
	sprintf(port_str, "%hu", port);
	if (strlen(wes) + strlen(port_str) >= AUTHN_NODE_KEY_LENGTH) {
		int substr_len = AUTHN_NODE_KEY_LENGTH - strlen(wes);
		char subbuff[substr_len];
		memcpy(subbuff, port_str, substr_len);
	} else {
		strcat(wes, port_str);
	}
	return wes;

}

unsigned authn_hash(char *s) {
	unsigned hashval;
	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;
	return hashval % AUTHN_HASHSIZE;
}

int authn_nodes_equal(authn_node_t *a1, authn_node_t *a2) {
	if (!a1 || !a2) return 0;
	return strcmp(a1->key, a2->key) == 0;
}

authn_node_t *lookup_authn_node(authn_hashtable_t *ahtbl, char *key) {

	if (!ahtbl) return NULL;
	authn_node_t *np;
	for (np = (*ahtbl)[authn_hash(key)]; np != NULL; np = np->next)
		if (strcmp(np->key, key) == 0)
			return np; /* found */
	return NULL; /* not found */
}

void remove_authn_node(authn_hashtable_t *ahtbl, char *key) {
	// TODO
}

authn_node_t *add_authn_node(authn_hashtable_t *ahtbl, AUTHN_STATUS status, char *key) {

	if (!ahtbl) return NULL;
	authn_node_t *np;
	unsigned hashval;
	if ((np = lookup_authn_node(ahtbl, key)) == NULL) { /* not found */
		np = malloc(SZ_AUN_ND);
		memset(np, '\0', SZ_AUN_ND);
		if (np == NULL) return NULL;
		np->status = status;
		strcpy(np->key, key);

		hashval = authn_hash(key);
		np->next = (*ahtbl)[hashval];
		(*ahtbl)[hashval] = np;
	}

	// TODO what should we do if lookup_user returns non-NULL?
	return np;
}

unsigned token_hash(unsigned char *s) {
	unsigned hashval;
	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;
	return hashval % AUTHN_HASHSIZE;
}

token_node_t *add_token_node(token_hashtable_t *thtbl, unsigned char *authn_token) {

	if (!thtbl) return NULL;
	token_node_t *np;
	unsigned hashval;
	if ((np = lookup_token_node(thtbl, authn_token)) == NULL) {
		np = malloc(SZ_TKN_ND);
		memset(np, '\0', SZ_TKN_ND);
		if (np == NULL) return NULL;
		memcpy(np->authn_token, authn_token, AUTHEN_TOKEN_LEN);

		hashval = token_hash(authn_token);
		printf("AAAAAAAAAAAAAAAAAAAAAAAAAA(%d)\n", hashval);
		np->next = (*thtbl)[hashval];
		(*thtbl)[hashval] = np;
	}

	return np;
}

token_node_t *lookup_token_node(token_hashtable_t *thtbl, unsigned char *authn_token) {

	if (!thtbl) return NULL;
	printf("LLLLLLLLLLLLLLLLLLLLLL(%d)\n", token_hash(authn_token));
	token_node_t *np;
	for (np = (*thtbl)[token_hash(authn_token)]; np != NULL; np = np->next)
		if (memcmp(np->authn_token, authn_token, AUTHEN_TOKEN_LEN) == 0)
			return np;
	return NULL;
}

int chatbuf_to_addr(chat_buf_t *cb, struct sockaddr **addr) {
	if (!cb || !addr) return -1;

	switch (cb->family) {
		case AF_INET: {
			struct sockaddr_in *sai = malloc(sizeof(struct sockaddr_in));
			sai->sin_addr.s_addr = cb->ip4;
			sai->sin_port = cb->port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sai = malloc(sizeof(struct sockaddr_in6));
			memcpy(sai->sin6_addr.s6_addr, cb->ip6, sizeof(unsigned char[16]));
			sai->sin6_port = cb->port;
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
