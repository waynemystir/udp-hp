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
} node;

// TODO I want to minimize network buffer: Remove next from node
// and make separate node_internal that includes next. Then add
// function to switch between node and node_internal and voila.

typedef struct LinkedList {
	struct node *first_node;
	struct node **last_node;
	int node_count;
} LinkedList;

int nodes_equal(struct node *n1, struct node *n2);

struct node *find_node(LinkedList *list, struct node *node);

struct node *register_node(LinkedList *list, struct node *new_node);

void nodes_perform(LinkedList *list, void (*perform)(struct node *node));