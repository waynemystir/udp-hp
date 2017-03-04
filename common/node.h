/********************************

Created by Wayne Small
March 2, 2017

*********************************/

typedef enum STATUS_TYPE {
    STATUS_INIT_NODE = 0,
    STATUS_NEW_NODE = 1,
    STATUS_CONFIRMED_NODE = 2,
    STATUS_NEW_PEER = 3 // A peer is any client other than self
} STATUS_TYPE;

typedef struct node {
	STATUS_TYPE status;
	union {
		unsigned long ip4;
		unsigned char ip6[16];
	};
	unsigned short port;
	unsigned short family;
	struct node *next;
} node_t;

// TODO I want to minimize network buffer: Remove next from node
// and make separate node_internal that includes next. Then add
// function to switch between node and node_internal and voila.

typedef struct LinkedList {
	node_t *head;
	node_t *tail;
	int node_count;
} LinkedList;

int nodes_equal(struct node *n1, struct node *n2);

struct node *find_node(LinkedList *list, struct node *node);

void copy_and_add_tail(LinkedList *list, node_t *node_to_copy, node_t **new_tail);

void get_new_tail(LinkedList *list, node_t **new_tail);

void nodes_perform(LinkedList *list, void (*perform)(node_t *node));

void free_list(LinkedList *list);