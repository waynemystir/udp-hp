//
//  node.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef node_h
#define node_h

#include <limits.h>

#include "common.h"

#define ID_LEN 20
#define IP6_ADDR_LEN 16

typedef enum STATUS_TYPE {
	STATUS_INIT_NODE = 0,
	STATUS_NEW_NODE = 1,
	STATUS_NOTIFY_EXISTING_CONTACT = 2,
	STATUS_STAY_IN_TOUCH = 3,
	STATUS_STAY_IN_TOUCH_RESPONSE = 4,
	STATUS_CONFIRMED_NODE = 5,
	STATUS_DEINIT_NODE = 6,
	STATUS_REQUEST_ADD_CONTACT_REQUEST = 7,
	STATUS_REQUEST_ADD_CONTACT_ACCEPT = 8,
	STATUS_REQUEST_ADD_CONTACT_DENIED = 9,
	STATUS_NEW_PEER = 10, // A peer is any client other than self
	STATUS_CONFIRMED_PEER = 11,
	STATUS_ACQUIRED_CHAT_PORT = 12,
	STATUS_PROCEED_CHAT_HP = 13,
	STATUS_CONFIRMED_CHAT_PEER = 14,
	STATUS_SIGN_OUT = 15,
} STATUS_TYPE;

typedef enum SEARCH_STATUS {
	SEARCH_STATUS_USERNAME = 0,
	SEARCH_STATUS_USERNAME_RESPONSE = 1,
} SEARCH_STATUS;

typedef struct node_buf {
	STATUS_TYPE status;
	char id[MAX_CHARS_USERNAME];
	unsigned char authn_token[AUTHEN_TOKEN_LEN];
	unsigned short int_or_ext; // 0 is internal and 1 is external
	union {
		in_addr_t ip4;
		unsigned char ip6[IP6_ADDR_LEN + 1];
		char other_id[MAX_CHARS_USERNAME];
	};
	in_port_t port;
	in_port_t chat_port;
	SUP_FAMILY_T family;
} node_buf_t;

typedef struct node {
	STATUS_TYPE status;
	unsigned char authn_token[AUTHEN_TOKEN_LEN];
	unsigned short int_or_ext; // 0 is internal and 1 is external
	union {
		in_addr_t internal_ip4;
		unsigned char internal_ip6[IP6_ADDR_LEN + 1];
	};
	in_port_t internal_port;
	in_port_t internal_chat_port;
	SUP_FAMILY_T internal_family;
	union {
		in_addr_t external_ip4;
		unsigned char external_ip6[IP6_ADDR_LEN + 1];
	};
	in_port_t external_port;
	in_port_t external_chat_port;
	SUP_FAMILY_T external_family;
	struct node *next;
} node_t;

typedef struct LinkedList {
	node_t *head;
	node_t *tail;
	int node_count;
} LinkedList_t;

typedef struct send_msg {
	node_t *n;
	CHAT_STATUS status;
	char msg[MAX_CHAT_MSG_LEN];
} send_msg_t;

typedef struct search_buf {
	SEARCH_STATUS status;
	char id[MAX_CHARS_USERNAME];
	unsigned char authn_token[AUTHEN_TOKEN_LEN];
	union {
		char search_text[MAX_CHARS_SEARCH];
		char search_results[MAX_SEARCH_RESULTS][MAX_CHARS_USERNAME];
	};
	int number_of_search_results;
	in_port_t main_port;
} search_buf_t;

extern const unsigned short INTERNAL_ADDR;
extern const unsigned short EXTERNAL_ADDR;

#define SZ_NODE_BF sizeof(node_buf_t)
#define SZ_NODE sizeof(node_t)
#define SZ_LINK_LIST sizeof(LinkedList_t)
#define SZ_SND_MSG sizeof(send_msg_t)
#define SZ_SRCH_BF sizeof(search_buf_t)
#define SZ_SOCKADDR sizeof(struct sockaddr)
#define SZ_SOCKADDR_IN sizeof(struct sockaddr_in)
#define SZ_SOCKADDR_IN6 sizeof(struct sockaddr_in6)

char *status_to_str(STATUS_TYPE st);
char *search_status_to_str(SEARCH_STATUS st);

// node_buf_t functions

void addr_to_node_buf(struct sockaddr *sa,
			node_buf_t **nb,
			STATUS_TYPE status,
			unsigned short int_or_ext,
			char id[MAX_CHARS_USERNAME]);

int node_buf_to_addr(node_buf_t *node_buf, struct sockaddr **addr);

void get_approp_node_bufs(node_t *n1, node_t *n2,
				node_buf_t **nb1, node_buf_t **nb2,
				char id1[MAX_CHARS_USERNAME], char id2[MAX_CHARS_USERNAME]);

// LinkedList and node_t functions

int same_nat(node_t *n1, node_t *n2);

int nodes_equal(node_t *n1, node_t *n2);

int node_and_node_buf_equal(node_t *n, node_buf_t *nb);

node_t *find_node(LinkedList_t *list, node_t *node);

int node_and_sockaddr_equal(node_t *node, struct sockaddr *addr, SERVER_TYPE st);

node_t *find_node_from_sockaddr(LinkedList_t *list, struct sockaddr *addr, SERVER_TYPE st);

void node_to_internal_addr(node_t *node, struct sockaddr **addr);

void node_to_external_addr(node_t *node, struct sockaddr **addr);

void node_internal_to_node_buf(node_t *node, node_buf_t **node_buf, char id[MAX_CHARS_USERNAME]);

void node_external_to_node_buf(node_t *node, node_buf_t **node_buf, char id[MAX_CHARS_USERNAME]);

void node_buf_to_node(node_buf_t *nb, node_t **n);

void copy_and_add_tail(LinkedList_t *list, node_t *node_to_copy, node_t **new_tail);

void copy_and_add_head(LinkedList_t *list, node_t *node_to_copy, node_t **new_head);

void get_new_tail(LinkedList_t *list, node_t **new_tail);

void get_new_head(LinkedList_t *list, node_t **new_head);

void nodes_perform(LinkedList_t *list,
		void (*perform)(node_t *node, void *arg1, void *arg2, void *arg3, void *arg4),
		void *arg1,
		void *arg2,
		void *arg3,
		void *arg4);

void remove_node_with_sockaddr(LinkedList_t *list, struct sockaddr *addr, SERVER_TYPE st);

void remove_node_with_node_buf(LinkedList_t *list, node_buf_t *nb);

void free_list(LinkedList_t *list);

#endif /* node_h */
