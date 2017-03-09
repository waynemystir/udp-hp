#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "node.h"

const unsigned short INTERNAL_ADDR = 0;
const unsigned short EXTERNAL_ADDR = 1;

void addr_to_node_buf(struct sockaddr *sa, node_buf_t **nb, STATUS_TYPE status, unsigned short int_or_ext) {
	if (!sa || !nb) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	*nb = new_node_buf;
	new_node_buf->status = status;
	new_node_buf->int_or_ext = int_or_ext;
	new_node_buf->family = sa->sa_family;
	switch (new_node_buf->family) {
		case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
			new_node_buf->ip4 = sa4->sin_addr.s_addr;
			new_node_buf->port = sa4->sin_port;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
			memcpy(new_node_buf->ip6, sa6->sin6_addr.s6_addr, sizeof(unsigned char[16]));
			new_node_buf->port = sa6->sin6_port;
			break;
		}
		default: break;
	}
}

int node_buf_to_addr(node_buf_t *node_buf, struct sockaddr **addr) {
	if (!addr || !node_buf) return -1;

	switch (node_buf->family) {
		case AF_INET: {
			struct sockaddr_in *sai = malloc(SZ_SOCKADDR_IN);
			sai->sin_addr.s_addr = node_buf->ip4;
			sai->sin_port = node_buf->port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sai = malloc(SZ_SOCKADDR_IN6);
			memcpy(sai->sin6_addr.s6_addr, node_buf->ip6, sizeof(unsigned char[16]));
			sai->sin6_port = node_buf->port;
			sai->sin6_family = AF_INET;
			*addr = (struct sockaddr*)&sai;
			(*addr)->sa_family = AF_INET6;
			break;
		}
		default: {
			break;
		}
	}

	return 0;
}

void node_buf_to_node_min(node_buf_t *nb, node_min_t **nm) {
	if (!nb || !nm) return;

	node_min_t *new_node_min = malloc(SZ_NODE_MN);
	*nm = new_node_min;
	new_node_min->next = NULL;
	new_node_min->status = nb->status;
	new_node_min->int_or_ext = nb->int_or_ext;
	new_node_min->port = nb->port;
	new_node_min->family = nb->family;
	switch (new_node_min->family) {
		case AF_INET: {
			new_node_min->ip4 = nb->ip4;
			break;
		}
		case AF_INET6: {
			memcpy(new_node_min->ip6, nb->ip6, 16);
			break;
		}
		default: break;
	}
}

void get_approp_node_bufs(node_t *n1, node_t *n2, node_buf_t **nb1, node_buf_t **nb2) {
	if (!n1 || !n2 || !nb1 || !nb2) return;

	if (same_nat(n1, n2)) {
		node_internal_to_node_buf(n1, nb1);
		node_internal_to_node_buf(n2, nb2);
	} else {
		node_external_to_node_buf(n1, nb1);
		node_external_to_node_buf(n2, nb2);
	}
}

int nodes_min_equal(node_min_t *n1, node_min_t *n2) {
	if (!n1 || !n2) return 0;
	if (n1->family != n2->family) return 0;
	if (n1->port != n2->port) return 0;

	switch (n1->family) {
		case AF_INET: return n1->ip4 == n2->ip4;
		case AF_INET6: return n1->ip6 == n2->ip6;
		default: return 0;
	}
}

node_min_t *find_node_min(LinkedList_min_t *list, node_min_t *node) {
	if (!list || !list->head) return NULL;

	node_min_t *p = list->head;
	while (p) {
		if (nodes_min_equal(p, node)) return p;
		p = p->next;
	}
	return NULL;
}

int node_min_and_sockaddr_equal(node_min_t *node, struct sockaddr *addr) {
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

node_min_t *find_node_min_from_sockaddr(LinkedList_min_t *list, struct sockaddr *addr) {
	if (!list || !addr) return NULL;

	node_min_t *p = list->head;
	while (p) {
		if (node_min_and_sockaddr_equal(p, addr)) return p;
		p = p->next;
	}
	return NULL;
}

void add_node_min(LinkedList_min_t *list, node_min_t *node) {
	if (!list || !node) return;
	node->next = NULL;

	if (!list->head) {
		list->head = node;
		list->tail = node;
	} else {
		list->tail->next = node;
		list->tail = node;
	}

	list->node_count++;
}

void nodes_min_perform(LinkedList_min_t *list, void (*perform)(node_min_t *node)) {
	if (!list || !list->head) return;

	node_min_t *p = list->head;
	while (p) {
		perform(p);
		p = p->next;
	}
}

int same_nat(node_t *n1, node_t *n2) {
	if (!n1 || !n2) return 0;
	if (n1->external_family != n2->external_family) return 0;

	switch (n1->external_family) {
		case AF_INET: return n1->external_ip4 == n2->external_ip4;
		case AF_INET6: return n1->external_ip6 == n2->external_ip6;
		default: return 0;
	}
}

int nodes_equal(node_t *n1, node_t *n2) {
	if (!n1 || !n2) return 0;
	if (n1->external_family != n2->external_family) return 0;
	if (n1->external_port != n2->external_port) return 0;

	switch (n1->external_family) {
		case AF_INET: return n1->external_ip4 == n2->external_ip4;
		case AF_INET6: return n1->external_ip6 == n2->external_ip6;
		default: return 0;
	}
}

struct node *find_node(LinkedList *list, node_t *node) {
	if (!list || !list->head) return NULL;

	node_t *p = list->head;
	while (p) {
		if (nodes_equal(p, node)) return p;
		p = p->next;
	}
	return NULL;
}

int node_and_sockaddr_equal(node_t *node, struct sockaddr *addr) {
	if (!node || !addr) return 0;
	if (node->external_family != addr->sa_family) return 0;

	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)addr;
			return node->external_ip4 == sa4->sin_addr.s_addr &&
				node->external_port == sa4->sin_port;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
			return node->external_ip6 == sa6->sin6_addr.s6_addr &&
				node->external_port == sa6->sin6_port;
		}
		default: return 0;
	}
}

struct node *find_node_from_sockaddr(LinkedList *list, struct sockaddr *addr) {
	if (!list || !list->head) return NULL;

	node_t *p = list->head;
	while (p) {
		if (node_and_sockaddr_equal(p, addr)) return p;
		p = p->next;
	}
	return NULL;
}

void node_to_internal_addr(node_t *node, struct sockaddr **addr) {
	if (!node || !addr) return;

	switch (node->internal_family) {
		case AF_INET: {
			struct sockaddr_in *sai = malloc(SZ_SOCKADDR_IN);
			sai->sin_addr.s_addr = node->internal_ip4;
			sai->sin_port = node->internal_port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sai = malloc(SZ_SOCKADDR_IN6);
			memcpy(sai->sin6_addr.s6_addr, node->internal_ip6, sizeof(unsigned char[16]));
			sai->sin6_port = node->internal_port;
			sai->sin6_family = AF_INET;
			*addr = (struct sockaddr*)&sai;
			(*addr)->sa_family = AF_INET6;
			break;
		}
		default: {
			break;
		}
	}
}

void node_internal_to_node_buf(node_t *node, node_buf_t **node_buf) {
	if (!node || !node_buf) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	*node_buf = new_node_buf;
	new_node_buf->status = node->status;
	new_node_buf->int_or_ext = INTERNAL_ADDR;
	new_node_buf->family = node->internal_family;
	new_node_buf->port = node->internal_port;
	switch (node->internal_family) {
		case AF_INET: {
			new_node_buf->ip4 = node->internal_ip4;
			break;
		}
		case AF_INET6: {
			memcpy(new_node_buf->ip6, node->internal_ip6, sizeof(unsigned char[16]));
			break;
		}
		default: break;
	}
}

void node_external_to_node_buf(node_t *node, node_buf_t **node_buf) {
	if (!node || !node_buf) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	*node_buf = new_node_buf;
	new_node_buf->status = node->status;
	new_node_buf->int_or_ext = EXTERNAL_ADDR;
	new_node_buf->family = node->external_family;
	new_node_buf->port = node->external_port;
	switch (node->external_family) {
		case AF_INET: {
			new_node_buf->ip4 = node->external_ip4;
			break;
		}
		case AF_INET6: {
			memcpy(new_node_buf->ip6, node->external_ip6, sizeof(unsigned char[16]));
			break;
		}
		default: break;
	}
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

	nn = malloc(SZ_NODE);
	*new_tail = nn;
	memset(nn, '\0', SZ_NODE);
	memcpy(nn, node_to_copy, SZ_NODE);
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
	memset(&ntc, '\0', SZ_NODE);
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
