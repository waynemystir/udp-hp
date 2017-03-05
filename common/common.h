

typedef enum CHAT_STATUS {
	CHAT_STATUS_INIT = 0,
	CHAT_STATUS_NEW_CHAT_HP = 1,
	CHAT_STATUS_MSG = 2,
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