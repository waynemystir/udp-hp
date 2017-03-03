#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "node.h"

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

struct node *find_node(LinkedList *list, struct node *node) {
	if (!list && !list->first_node) return NULL;

	struct node *p = list->first_node;
	while (p) {
		if (nodes_equal(p, node)) return p;
		p = p->next;
	}
	return NULL;
}

struct node *register_node(LinkedList *list, struct node *new_node) {
	if (!list) {
		printf("register_node: given list is NULL, returning NULL\n");
		return NULL;
	}

	if (!list->first_node) {
		list->first_node = malloc(sizeof(struct node));
		memcpy(list->first_node, new_node, sizeof(struct node));
		list->last_node = &list->first_node;
		list->node_count++;
		return list->first_node;
	}

	if (find_node(list, new_node)) {
		printf("register_node: node already in list, returning NULL\n");
		return NULL;
	}

	struct node *old_last_node = *list->last_node;
	struct node *new_last_node = malloc(sizeof(struct node));
	memcpy(new_last_node, new_node, sizeof(struct node));
	old_last_node->next = new_last_node;
	list->last_node = &new_last_node;
	list->node_count++;
	return new_last_node;
}

void nodes_perform(LinkedList *list, void (*perform)(struct node *n)) {
	if (!list && !list->first_node) return;

	struct node *p = list->first_node;
	while (p) {
		perform(p);
		p = p->next;
	}
}