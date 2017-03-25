#include <stdlib.h>
#include <string.h>

#include "common.h"

const unsigned short AUTHENTICATION_PORT = 9929;

void str_from_server_type(SERVER_TYPE st, char str[15]) {
	switch (st) {
		case SERVER_SIGNIN: {
			strcpy(str, "SERVER_SIGNIN");
			break;
		}
		case SERVER_CHAT: {
			strcpy(str, "SERVER_CHAT");
			break;
		}
		default: {
			strcpy(str, "UNKNOWN");
			break;
		}
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