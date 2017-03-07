//
//  common.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef common_h
#define common_h

typedef enum CHAT_STATUS {
	CHAT_STATUS_INIT = 0,
	CHAT_STATUS_NEW = 1,
	CHAT_STATUS_STAY_IN_TOUCH = 2,
	CHAT_STATUS_STAY_IN_TOUCH_RESPONSE = 3,
} CHAT_STATUS;

typedef struct chat_buf {
	CHAT_STATUS status;
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short family;

} chat_buf_t;

#endif /* common_h */