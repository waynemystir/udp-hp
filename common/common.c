#include <stdlib.h>
#include <string.h>

#include "common.h"

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