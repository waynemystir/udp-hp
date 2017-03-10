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

typedef enum SERVER_TYPE {
	SERVER_SIGNIN,
	SERVER_CHAT,
} SERVER_TYPE;

typedef enum CHAT_STATUS {
	CHAT_STATUS_INIT = 0,
	CHAT_STATUS_NEW = 1,
	CHAT_STATUS_STAY_IN_TOUCH = 2,
	CHAT_STATUS_STAY_IN_TOUCH_RESPONSE = 3,
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

void str_from_server_type(SERVER_TYPE st, char str[15]);

int chatbuf_to_addr(chat_buf_t *cb, struct sockaddr **addr);

#define SZ_CH_BF sizeof(chat_buf_t)

#endif /* common_h */
