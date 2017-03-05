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
	if (!list || !list->head) return NULL;

	struct node *p = list->head;
	while (p) {
		if (nodes_equal(p, node)) return p;
		p = p->next;
	}
	return NULL;
}

int node_and_sockaddr_equal(node_t *node, struct sockaddr *addr) {
	if (!node || !addr) return 0;
	if (node->family != addr->sa_family) return 0;

	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)addr;
			return node->ip4 == sa4->sin_addr.s_addr &&
				node->port == sa4->sin_port;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
			return node->ip6 == sa6->sin6_addr.s6_addr &&
				node->port == sa6->sin6_port;
		}
		default: return 0;
	}
}

struct node *find_node_from_sockaddr(LinkedList *list, struct sockaddr *addr) {
	if (!list || !list->head) return NULL;

	struct node *p = list->head;
	while (p) {
		if (node_and_sockaddr_equal(p, addr)) return p;
		p = p->next;
	}
	return NULL;
}

void copy_and_add_tail(LinkedList *list, node_t *node_to_copy, node_t **new_tail) {
	if (!list) {
		printf("copy_and_add_tail: given list is NULL, returning NULL\n");
		return;
	}

	if (!new_tail) {
		printf("copy_and_add_tail: given new_tail parameter is NULL\n");
		return;
	}

	node_t *nn;

	nn = malloc(sizeof(node_t));
	*new_tail = nn;
	memset(nn, '\0', sizeof(node_t));
	memcpy(nn, node_to_copy, sizeof(node_t));
	nn->next = NULL;

	if (!list->head) {
		list->head = nn;
		list->tail = nn;
	} else {
		list->tail->next = nn;
		list->tail = nn;
	}

	list->node_count++;
}

void get_new_tail(LinkedList *list, node_t **new_tail) {
	if (!new_tail) return;
	node_t ntc;
	memset(&ntc, '\0', sizeof(node_t));
	copy_and_add_tail(list, &ntc, new_tail);
}

void nodes_perform(LinkedList *list, void (*perform)(node_t *n)) {
	if (!list || !list->head) return;

	node_t *p = list->head;
	while (p) {
		perform(p);
		p = p->next;
	}
}

void free_list(LinkedList *list) {
	if (!list || !list->head) return;
	node_t *tmp;
	while ((tmp = list->head) != NULL) {
		list->head = list->head->next;
		free(tmp);
	}

	free(list);
}
