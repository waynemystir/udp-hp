//
//  node.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef node_h
#define node_h

typedef enum STATUS_TYPE {
    STATUS_INIT_NODE = 0,
    STATUS_NEW_NODE = 1,
    STATUS_STAY_IN_TOUCH = 2,
    STATUS_STAY_IN_TOUCH_RESPONSE = 3,
    STATUS_CONFIRMED_NODE = 4,
    STATUS_NEW_PEER = 5, // A peer is any client other than self
    STATUS_CONFIRMED_PEER = 6,
    STATUS_CHAT_PORT = 7,
} STATUS_TYPE;

typedef struct node_buf {
	STATUS_TYPE status;
	unsigned short int_or_ext; // 0 is internal and 1 is external
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short chat_port;
	unsigned short family;
} node_buf_t;

typedef struct node_min {
	STATUS_TYPE status;
	unsigned short int_or_ext; // 0 is internal and 1 is external
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short chat_port;
	unsigned short family;
	struct node_min *next;
} node_min_t;

typedef struct node {
	STATUS_TYPE status;
	unsigned short int_or_ext; // 0 is internal and 1 is external
	union {
		unsigned long internal_ip4;
		unsigned char internal_ip6[16];
	};
	unsigned short internal_port;
	unsigned short internal_chat_port;
	unsigned short internal_family;
	union {
		unsigned long external_ip4;
		unsigned char external_ip6[16];
	};
	unsigned short external_port;
	unsigned short external_chat_port;
	unsigned short external_family;
	struct node *next;
} node_t;

typedef struct LinkedList_min {
	node_min_t *head;
	node_min_t *tail;
	int node_count;
} LinkedList_min_t;

typedef struct LinkedList {
	node_t *head;
	node_t *tail;
	int node_count;
} LinkedList;

#define SZ_NODE_BF sizeof(node_buf_t)
#define SZ_NODE_MN sizeof(node_min_t)
#define SZ_NODE sizeof(node_t)
#define SZ_LINK_LIST_MN sizeof(LinkedList_min_t)
#define SZ_LINK_LIST sizeof(LinkedList)
#define SZ_SOCKADDR sizeof(struct sockaddr)
#define SZ_SOCKADDR_IN sizeof(struct sockaddr_in)
#define SZ_SOCKADDR_IN6 sizeof(struct sockaddr_in6)

// LinkedList_min and node_min_t functions

void addr_to_node_buf(struct sockaddr *sa, node_buf_t **nb, STATUS_TYPE status, unsigned short int_or_ext);

int node_buf_to_addr(node_buf_t *node_buf, struct sockaddr **addr);

void node_buf_to_node_min(node_buf_t *nb, node_min_t **nm);

int nodes_min_equal(node_min_t *n1, node_min_t *n2);

node_min_t *find_node_min(LinkedList_min_t *list, node_min_t *node);

int node_min_and_sockaddr_equal(node_min_t *node, struct sockaddr *addr);

node_min_t *find_node_min_from_sockaddr(LinkedList_min_t *list, struct sockaddr *addr);

void add_node_min(LinkedList_min_t *list, node_min_t *node);

void nodes_min_perform(LinkedList_min_t *list, void (*perform)(node_min_t *node));

// LinkedList and node_t functions

int nodes_equal(node_t *n1, node_t *n2);

struct node *find_node(LinkedList *list, node_t *node);

int node_and_sockaddr_equal(node_t *node, struct sockaddr *addr);

struct node *find_node_from_sockaddr(LinkedList *list, struct sockaddr *addr);

void copy_and_add_tail(LinkedList *list, node_t *node_to_copy, node_t **new_tail);

void get_new_tail(LinkedList *list, node_t **new_tail);

void nodes_perform(LinkedList *list, void (*perform)(node_t *node));

void free_list(LinkedList *list);

#endif /* node_h */
