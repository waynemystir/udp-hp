#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "node.h"

struct node *first_peer = NULL;
struct node **last_peer = &first_peer;
int peer_count = 0;

int nodes_equal(struct node *n1, struct node *n2) {
	if (!n1 || !n2) return 0;
	if (n1->family != n2->family) return 0;
	if (n1->port != n2->port) return 0;

	switch (n1->family) {
		case AF_INET: return n1->ip4 == n2->ip4;
		case AF_INET6: return n1->ip6 == n2->ip6;
		default: return 0;
	}
}

struct node *find_peer(struct node peer) {
	if (!first_peer) return NULL;

	struct node *p = first_peer;
	while (p) {
		if (nodes_equal(p, &peer)) return p;
		p = p->next;
	}
	return NULL;
}

struct node *register_peer(struct node new_peer) {
	if (!first_peer) {
		first_peer = malloc(sizeof(struct node));
		memcpy(first_peer, &new_peer, sizeof(struct node));
		peer_count++;
		return first_peer;
	}

	if (find_peer(new_peer)) return NULL;

	struct node *old_last_peer = *last_peer;
	struct node *new_last_peer = malloc(sizeof(struct node));
	memcpy(new_last_peer, &new_peer, sizeof(struct node));
	old_last_peer->next = new_last_peer;
	last_peer = &new_last_peer;
	peer_count++;
	return new_last_peer;
}

void peers_perform(void (*perform)(struct node *n)) {
	if (!first_peer || !perform) return;

	struct node *p = first_peer;
	while (p) {
		perform(p);
		p = p->next;
	}
}