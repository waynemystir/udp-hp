//
//  common.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef common_h
#define common_h

#ifdef __APPLE__
    #include "TargetConditionals.h"
    #if TARGET_IPHONE_SIMULATOR
         // iOS Simulator
    #elif TARGET_OS_IPHONE
        // iOS device
    #elif TARGET_OS_MAC
        #include <_in_addr_t.h>
    #endif
#endif

typedef enum SERVER_TYPE {
	SERVER_SIGNIN,
	SERVER_CHAT,
} SERVER_TYPE;

void str_from_server_type(SERVER_TYPE st, char str[15]);

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
	unsigned short port;
	unsigned short family;

} chat_buf_t;

#endif /* common_h */
