#include <stdlib.h>
#include <string.h>

#include "common.h"

const unsigned short AUTHENTICATION_PORT = 9929;

char *authn_status_to_str(AUTHN_STATUS as) {
	switch (as) {
		case AUTHN_STATUS_RSA_SWAP: return "AUTHN_STATUS_RSA_SWAP";
		case AUTHN_STATUS_RSA_SWAP_RESPONSE: return "AUTHN_STATUS_RSA_SWAP_RESPONSE";
		case AUTHN_STATUS_AES_SWAP: return "AUTHN_STATUS_AES_SWAP";
		case AUTHN_STATUS_AES_SWAP_RESPONSE: return "AUTHN_STATUS_AES_SWAP_RESPONSE";
		case AUTHN_STATUS_NEW_USER: return "AUTHN_STATUS_NEW_USER";
		case AUTHN_STATUS_NEW_USER_RESPONSE: return "AUTHN_STATUS_NEW_USER_RESPONSE";
		case AUTHN_STATUS_AUTH_TOKEN: return "AUTHN_STATUS_AUTH_TOKEN";
		case AUTHN_STATUS_AUTH_TOKEN_RESPONSE: return "AUTHN_STATUS_AUTH_TOKEN_RESPONSE";
		case AUTHN_STATUS_SIGN_OUT: return "AUTHN_STATUS_SIGN_OUT";
		default: return "AUTHN_STATUS_UNKNOWN";
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