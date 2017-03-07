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