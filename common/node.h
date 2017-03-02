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

int nodes_equal(struct node *n1, struct node *n2);

struct node *find_peer(struct node peer);

struct node *register_peer(struct node new_peer);

void peers_perform(void (*perform)(struct node *n));