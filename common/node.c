#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

#include "node.h"

const unsigned short INTERNAL_ADDR = 0;
const unsigned short EXTERNAL_ADDR = 1;

char *status_to_str(STATUS_TYPE st) {
	switch (st) {
		case STATUS_INIT_NODE: return "STATUS_INIT_NODE";
		case STATUS_NEW_NODE: return "STATUS_NEW_NODE";
		case STATUS_NOTIFY_EXISTING_CONTACT: return "STATUS_NOTIFY_EXISTING_CONTACT";
		case STATUS_STAY_IN_TOUCH: return "STATUS_STAY_IN_TOUCH";
		case STATUS_STAY_IN_TOUCH_RESPONSE: return "STATUS_STAY_IN_TOUCH_RESPONSE";
		case STATUS_CONFIRMED_NODE: return "STATUS_CONFIRMED_NODE";
		case STATUS_DEINIT_NODE: return "STATUS_DEINIT_NODE";
		case STATUS_REQUEST_ADD_CONTACT_REQUEST: return "STATUS_REQUEST_ADD_CONTACT_REQUEST";
		case STATUS_REQUEST_ADD_CONTACT_ACCEPT: return "STATUS_REQUEST_ADD_CONTACT_ACCEPT";
		case STATUS_REQUEST_ADD_CONTACT_DENIED: return "STATUS_REQUEST_ADD_CONTACT_DENIED";
		case STATUS_NEW_PEER: return "STATUS_NEW_PEER";
		case STATUS_CONFIRMED_PEER: return "STATUS_CONFIRMED_PEER";
		case STATUS_ACQUIRED_CHAT_PORT: return "STATUS_ACQUIRED_CHAT_PORT";
		case STATUS_PROCEED_CHAT_HP: return "STATUS_PROCEED_CHAT_HP";
		case STATUS_CONFIRMED_CHAT_PEER: return "STATUS_CONFIRMED_CHAT_PEER";
		case STATUS_SIGN_OUT: return "STATUS_SIGN_OUT";
		default: return "STATUS_UNKNOWN";
	}
}

char *search_status_to_str(SEARCH_STATUS st) {
	switch (st) {
		case SEARCH_STATUS_USERNAME: return "SEARCH_STATUS_USERNAME";
		case SEARCH_STATUS_USERNAME_RESPONSE: return "SEARCH_STATUS_USERNAME_RESPONSE";
		default: return "SEARCH_STATUS_UNKNOWN";
	}
}

void addr_to_node_buf(struct sockaddr *sa,
			node_buf_t **nb,
			STATUS_TYPE status,
			unsigned short int_or_ext,
			char id[MAX_CHARS_USERNAME]) {
	if (!sa || !nb) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	memset(new_node_buf, '\0', SZ_NODE_BF);
	*nb = new_node_buf;
	new_node_buf->status = status;
	strcpy(new_node_buf->id, id);
	new_node_buf->int_or_ext = int_or_ext;
	new_node_buf->family = sa_fam_to_sup_fam(sa->sa_family);

	switch (new_node_buf->family) {
		case SUP_AF_4_via_6: {
			// This should never occur
		}
		case SUP_AF_INET_4: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
			new_node_buf->ip4 = sa4->sin_addr.s_addr;
			new_node_buf->port = sa4->sin_port;
			break;
		}
		case SUP_AF_INET_6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
			memcpy(new_node_buf->ip6, sa6->sin6_addr.s6_addr, IP6_ADDR_LEN);
			new_node_buf->port = sa6->sin6_port;
			break;
		}
		default: break;
	}
}

int node_buf_to_addr(node_buf_t *node_buf, struct sockaddr **addr) {
	if (!addr || !node_buf) return -1;

	SUP_FAMILY_T sup_fam = node_buf->family == SUP_AF_4_via_6 ? SUP_AF_INET_6 : node_buf->family;

	switch (sup_fam) {
		case SUP_AF_INET_4: {
			struct sockaddr_in *sai = malloc(SZ_SOCKADDR_IN);
			memset(sai, '\0', SZ_SOCKADDR_IN);
			sai->sin_addr.s_addr = node_buf->ip4;
			sai->sin_port = node_buf->port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case SUP_AF_INET_6: {
			struct sockaddr_in6 *sai = malloc(SZ_SOCKADDR_IN6);
			memset(sai, '\0', SZ_SOCKADDR_IN6);
			memcpy(sai->sin6_addr.s6_addr, node_buf->ip6, IP6_ADDR_LEN);
			sai->sin6_port = node_buf->port;
			sai->sin6_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET6;
			break;
		}
		default: {
			break;
		}
	}

	return 0;
}

void get_approp_node_bufs(node_t *n1, node_t *n2,
				node_buf_t **nb1, node_buf_t **nb2,
				char id1[MAX_CHARS_USERNAME], char id2[MAX_CHARS_USERNAME]) {
	if (!n1 || !n2 || !nb1 || !nb2) return;

	if (same_nat(n1, n2)) {
		node_internal_to_node_buf(n1, nb1, id1);
		node_internal_to_node_buf(n2, nb2, id2);
	} else {
		node_external_to_node_buf(n1, nb1, id1);
		node_external_to_node_buf(n2, nb2, id2);
	}
}

int same_nat(node_t *n1, node_t *n2) {
	if (!n1 || !n2) return 0;
	if (n1->external_family != n2->external_family) return 0;

	switch (n1->external_family) {
		case SUP_AF_INET_4: return n1->external_ip4 == n2->external_ip4;
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: return memcmp(n1->external_ip6, n2->external_ip6, IP6_ADDR_LEN) == 0;
		default: return 0;
	}
}

int nodes_equal(node_t *n1, node_t *n2) {
	if (!n1 || !n2) return 0;
	if (n1->int_or_ext != n2->int_or_ext) return 0;

	SUP_FAMILY_T n1_fam = n1->int_or_ext == INTERNAL_ADDR ? n1->internal_family : n1->external_family;
	SUP_FAMILY_T n2_fam = n2->int_or_ext == INTERNAL_ADDR ? n2->internal_family : n2->external_family;
	if (n1_fam != n2_fam) return 0;

	in_port_t n1_port = n1->int_or_ext == INTERNAL_ADDR ? n1->internal_port : n1->external_port;
	in_port_t n2_port = n2->int_or_ext == INTERNAL_ADDR ? n2->internal_port : n2->external_port;
	if (n1_port != n2_port) return 0;

	switch (n1_fam) {
		case SUP_AF_INET_4: {
			in_addr_t n1_ip4 = n1->int_or_ext == INTERNAL_ADDR ? n1->internal_ip4 : n1->external_ip4;
			in_addr_t n2_ip4 = n2->int_or_ext == INTERNAL_ADDR ? n2->internal_ip4 : n2->external_ip4;
			return n1_ip4 == n2_ip4;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			unsigned char n1_ip6[IP6_ADDR_LEN];
			memcpy(n1_ip6, n1->int_or_ext == INTERNAL_ADDR ? n1->internal_ip6 : n1->external_ip6, IP6_ADDR_LEN);
			unsigned char n2_ip6[IP6_ADDR_LEN];
			memcpy(n2_ip6, n2->int_or_ext == INTERNAL_ADDR ? n2->internal_ip6 : n2->external_ip6, IP6_ADDR_LEN);
			return memcmp(n1_ip6, n2_ip6, IP6_ADDR_LEN) == 0;
		}
		default: return 0;
	}
}

int node_and_node_buf_equal(node_t *n, node_buf_t *nb) {
	if (!n || !nb) return 0;
	node_t nb_node;
	memset(&nb_node, '\0', SZ_NODE);
	nb_node.status = nb->status;
	nb_node.int_or_ext = nb->int_or_ext;
	if (nb_node.int_or_ext == INTERNAL_ADDR) {
		nb_node.internal_family = nb->family;
		switch (nb_node.internal_family) {
			case SUP_AF_INET_4: {
				nb_node.internal_ip4 = nb->ip4;
				break;
			}
			case SUP_AF_4_via_6:
			case SUP_AF_INET_6: {
				memcpy(nb_node.internal_ip6, nb->ip6, IP6_ADDR_LEN);
				break;
			}
			default: break;
		}
		nb_node.internal_port = nb->port;
		nb_node.internal_chat_port = nb->chat_port;
	} else {
		nb_node.external_family = nb->family;
		switch (nb_node.external_family) {
			case SUP_AF_INET_4: {
				nb_node.external_ip4 = nb->ip4;
				break;
			}
			case SUP_AF_4_via_6:
			case SUP_AF_INET_6: {
				memcpy(nb_node.external_ip6, nb->ip6, IP6_ADDR_LEN);
				break;
			}
			default: break;
		}
		nb_node.external_port = nb->port;
		nb_node.external_chat_port = nb->chat_port;
	}

	return nodes_equal(&nb_node, n);
}

struct node *find_node(LinkedList_t *list, node_t *node) {
	if (!list || !list->head) return NULL;

	node_t *p = list->head;
	while (p) {
		if (nodes_equal(p, node)) return p;
		p = p->next;
	}
	return NULL;
}

int node_logit = 0;

int node_and_sockaddr_equal(node_t *node, struct sockaddr *addr, SERVER_TYPE st) {
	if (!node || !addr) return 0;
	SUP_FAMILY_T sup_fam = node->int_or_ext == INTERNAL_ADDR ? node->internal_family : node->external_family;
	if (sup_fam != SUP_AF_4_via_6) {
		sa_family_t sa_fam = sup_fam_to_sa_fam(sup_fam);
		if (sa_fam != addr->sa_family) return 0;
	}
	in_port_t aport;
	switch (st) {
		case SERVER_SEARCH:
		case SERVER_MAIN: {
			aport = node->int_or_ext == INTERNAL_ADDR ? node->internal_port : node->external_port;
			break;
		}
		case SERVER_CHAT: {
			aport = node->int_or_ext == INTERNAL_ADDR ? node->internal_chat_port : node->external_chat_port;
			break;
		}
		default: return 0;
	}

	switch (sup_fam) {
		case SUP_AF_INET_4: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)addr;
			in_addr_t ip4 = node->int_or_ext == INTERNAL_ADDR ? node->internal_ip4 : node->external_ip4;
			return ip4 == sa4->sin_addr.s_addr &&
				aport == sa4->sin_port;
		}
		case SUP_AF_4_via_6: {
			if (addr->sa_family == AF_INET) {
				unsigned char ip6[IP6_ADDR_LEN] = {0};
				memcpy(ip6, node->int_or_ext == INTERNAL_ADDR ? node->internal_ip6 : node->external_ip6, IP6_ADDR_LEN);

				void *wayne = malloc(4);
				memset(wayne, '\0', 4);
				memcpy(wayne, &(ip6[12]), 4);
				in_addr_t ip4 = *(in_addr_t*)wayne;

				struct sockaddr_in *sa4 = (struct sockaddr_in *)addr;
				return ip4 == sa4->sin_addr.s_addr &&
					aport == sa4->sin_port;
			}
		}
		case SUP_AF_INET_6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)addr;
			unsigned char ip6[IP6_ADDR_LEN] = {0};
			memcpy(ip6, node->int_or_ext == INTERNAL_ADDR ? node->internal_ip6 : node->external_ip6, IP6_ADDR_LEN);
			if (node_logit) {
				wlog("UUUUUUUUUUUUUUUUUUUUUUU lets compare IPv6's\n");
				for (int i = 0; i < 16; i++) {
					wlog("ip6(%u) sa6(%u) hey(%s)\n", ip6[i], sa6->sin6_addr.s6_addr[i]
						, ip6[i] == sa6->sin6_addr.s6_addr[i] ? "EQUALS" : "NOT");
				}
				int ae = memcmp(ip6, sa6->sin6_addr.s6_addr, IP6_ADDR_LEN);
				wlog("IIE a(%d) p(%d)(%d)(%d)\n", ae, aport == sa6->sin6_port, ntohs(aport), ntohs(sa6->sin6_port));
			}
			return memcmp(ip6, sa6->sin6_addr.s6_addr, IP6_ADDR_LEN) == 0 &&
				aport == sa6->sin6_port;
		}
		default: return 0;
	}
}

struct node *find_node_from_sockaddr(LinkedList_t *list, struct sockaddr *addr, SERVER_TYPE st) {
	if (!list || !list->head) return NULL;

	node_t *p = list->head;
	while (p) {
		if (node_and_sockaddr_equal(p, addr, st)) return p;
		p = p->next;
	}
	return NULL;
}

void node_to_internal_addr(node_t *node, struct sockaddr **addr) {
	if (!node || !addr) return;

	switch (node->internal_family) {
		case SUP_AF_INET_4: {
			struct sockaddr_in *sai = malloc(SZ_SOCKADDR_IN);
			sai->sin_addr.s_addr = node->internal_ip4;
			sai->sin_port = node->internal_port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case SUP_AF_INET_6: {
			struct sockaddr_in6 *sai = malloc(SZ_SOCKADDR_IN6);
			memcpy(sai->sin6_addr.s6_addr, node->internal_ip6, IP6_ADDR_LEN);
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

void node_to_external_addr(node_t *node, struct sockaddr **addr) {
	if (!node || !addr) return;

	switch (node->external_family) {
		case SUP_AF_INET_4: {
			struct sockaddr_in *sai = malloc(SZ_SOCKADDR_IN);
			memset(sai, '\0', SZ_SOCKADDR_IN);
			sai->sin_addr.s_addr = node->external_ip4;
			sai->sin_port = node->external_port;
			sai->sin_family = AF_INET;
			*addr = (struct sockaddr*)sai;
			(*addr)->sa_family = AF_INET;
			break;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			struct sockaddr_in6 *sai6 = malloc(SZ_SOCKADDR_IN6);
			memset(sai6, '\0', SZ_SOCKADDR_IN6);
			memcpy(sai6->sin6_addr.s6_addr, node->external_ip6, 16);
			sai6->sin6_port = node->external_port;
			sai6->sin6_family = AF_INET6;
			*addr = (struct sockaddr*)sai6;
			(*addr)->sa_family = AF_INET6;
			break;
		}
		default: {
			break;
		}
	}
}

void node_internal_to_node_buf(node_t *node, node_buf_t **node_buf, char id[MAX_CHARS_USERNAME]) {
	if (!node || !node_buf) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	memset(new_node_buf, '\0', SZ_NODE_BF);
	*node_buf = new_node_buf;
	new_node_buf->status = node->status;
	strcpy(new_node_buf->id, id);
	new_node_buf->int_or_ext = INTERNAL_ADDR;
	new_node_buf->family = node->internal_family;
	new_node_buf->port = node->internal_port;
	new_node_buf->chat_port = node->internal_chat_port;
	switch (node->internal_family) {
		case SUP_AF_4_via_6:
		case SUP_AF_INET_4: {
			new_node_buf->ip4 = node->internal_ip4;
			break;
		}
		case SUP_AF_INET_6: {
			memcpy(new_node_buf->ip6, node->internal_ip6, IP6_ADDR_LEN);
			break;
		}
		default: break;
	}
}

void node_external_to_node_buf(node_t *node, node_buf_t **node_buf, char id[MAX_CHARS_USERNAME]) {
	if (!node || !node_buf) return;

	node_buf_t *new_node_buf = malloc(SZ_NODE_BF);
	memset(new_node_buf, '\0', SZ_NODE_BF);
	*node_buf = new_node_buf;
	new_node_buf->status = node->status;
	strcpy(new_node_buf->id, id);
	new_node_buf->int_or_ext = EXTERNAL_ADDR;
	new_node_buf->family = node->external_family;
	new_node_buf->port = node->external_port;
	new_node_buf->chat_port = node->external_chat_port;
//	printf("node_external_to_node_buf id(%s)(%s)(%d)\n", id, new_node_buf->id, new_node_buf->family);
	switch (node->external_family) {
		case SUP_AF_INET_4: {
			new_node_buf->ip4 = node->external_ip4;
			break;
		}
		case SUP_AF_4_via_6:
		case SUP_AF_INET_6: {
			memcpy(new_node_buf->ip6, node->external_ip6, IP6_ADDR_LEN);
			break;
		}
		default: break;
	}
}

void node_buf_to_node(node_buf_t *nb, node_t **n) {
	if (!nb || !n) return;

	node_t *new_node = malloc(SZ_NODE);
	*n = new_node;
	new_node->status = nb->status;
	new_node->int_or_ext = nb->int_or_ext;
	if (new_node->int_or_ext == INTERNAL_ADDR) {
		new_node->internal_family = nb->family;
		switch (new_node->internal_family) {
			case SUP_AF_4_via_6:
			case SUP_AF_INET_4: {
				new_node->internal_ip4 = nb->ip4;
				break;
			}
			case SUP_AF_INET_6: {
				memcpy(new_node->internal_ip6, nb->ip6, IP6_ADDR_LEN);
				break;
			}
			default: break;
		}
		new_node->internal_port = nb->port;
		new_node->internal_chat_port = nb->chat_port;
	} else {
		new_node->external_family = nb->family;
		switch (new_node->external_family) {
			case SUP_AF_INET_4: {
				new_node->external_ip4 = nb->ip4;
				break;
			}
			case SUP_AF_4_via_6:
			case SUP_AF_INET_6: {
				memcpy(new_node->external_ip6, nb->ip6, IP6_ADDR_LEN);
				break;
			}
			default: break;
		}
		new_node->external_port = nb->port;
		new_node->external_chat_port = nb->chat_port;
	}
}

void copy_and_add_tail(LinkedList_t *list, node_t *node_to_copy, node_t **new_tail) {
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

void copy_and_add_head(LinkedList_t *list, node_t *node_to_copy, node_t **new_head) {
	if (!list) {
		printf("copy_and_add_tail: given list is NULL, returning NULL\n");
		return;
	}

	if (!new_head) {
		printf("copy_and_add_head: given new_head parameter is NULL\n");
		return;
	}

	node_t *nn;

	nn = malloc(SZ_NODE);
	*new_head = nn;
	memset(nn, '\0', SZ_NODE);
	memcpy(nn, node_to_copy, SZ_NODE);
	nn->next = NULL;

	if (!list->head) {
		list->head = nn;
		list->tail = nn;
	} else {
		nn->next = list->head;
		list->head = nn;
	}

	list->node_count++;
}

void get_new_tail(LinkedList_t *list, node_t **new_tail) {
	if (!new_tail) return;
	node_t ntc;
	memset(&ntc, '\0', SZ_NODE);
	copy_and_add_tail(list, &ntc, new_tail);
}

void get_new_head(LinkedList_t *list, node_t **new_head) {
	if (!new_head) return;
	node_t ntc;
	memset(&ntc, '\0', SZ_NODE);
	copy_and_add_head(list, &ntc, new_head);
}

void nodes_perform(LinkedList_t *list,
		void (*perform)(node_t *node, void *arg1, void *arg2, void *arg3, void *arg4),
		void *arg1,
		void *arg2,
		void *arg3,
		void *arg4) {

	if (!list || !list->head) return;

	node_t *p = list->head;
	while (p) {
		perform(p, arg1, arg2, arg3, arg4);
		p = p->next;
	}
}

// curtesy of https://www.cs.bu.edu/teaching/c/linked-list/delete/
node_t *removeNode(node_t *currP, struct sockaddr *addr, SERVER_TYPE st, int *num_nodes_removed, node_t **new_tail) {
	/* See if we are at end of list. */
	if (currP == NULL) return NULL;

	/*
	* Check to see if current node is one
	* to be deleted.
	*/
	if (node_and_sockaddr_equal(currP, addr, st)) {
		node_t *tempNextP;

		/* Save the next pointer in the node. */
		tempNextP = currP->next;

		/* Deallocate the node. */
		free(currP);
		if (num_nodes_removed) (*num_nodes_removed)++;

		/*
		* Return the NEW pointer to where we
		* were called from.  I.e., the pointer
		* the previous call will use to "skip
		* over" the removed node.
		*/
		return tempNextP;
	}

	/*
	* Check the rest of the list, fixing the next
	* pointer in case the next node is the one
	* removed.
	*/
	currP->next = removeNode(currP->next, addr, st, num_nodes_removed, new_tail);
	if (!currP->next && new_tail) *new_tail = currP;

	/*
	* Return the pointer to where we were called
	* from.  Since we did not remove this node it
	* will be the same.
	*/
	return currP;
}

void remove_node_with_sockaddr(LinkedList_t *list, struct sockaddr *addr, SERVER_TYPE st) {
	if (!list || !addr) return;
	int num_nodes_removed = 0;
	node_t *new_tail = NULL;
	list->head = removeNode(list->head, addr, st, &num_nodes_removed, &new_tail);
	if (new_tail) list->tail = new_tail;
	list->node_count = list->node_count - num_nodes_removed;
}

// curtesy of https://www.cs.bu.edu/teaching/c/linked-list/delete/
node_t *remove_node_with_node_buf_internal(node_t *currP, node_buf_t *nb, int *num_nodes_removed, node_t **new_tail) {
	/* See if we are at end of list. */
	if (currP == NULL) return NULL;

	/*
	* Check to see if current node is one
	* to be deleted.
	*/
	if (node_and_node_buf_equal(currP, nb)) {
		node_t *tempNextP;

		/* Save the next pointer in the node. */
		tempNextP = currP->next;

		/* Deallocate the node. */
		free(currP);
		if (num_nodes_removed) (*num_nodes_removed)++;

		/*
		* Return the NEW pointer to where we
		* were called from.  I.e., the pointer
		* the previous call will use to "skip
		* over" the removed node.
		*/
		return tempNextP;
	}

	/*
	* Check the rest of the list, fixing the next
	* pointer in case the next node is the one
	* removed.
	*/
	currP->next = remove_node_with_node_buf_internal(currP->next, nb, num_nodes_removed, new_tail);
	if (!currP->next && new_tail) *new_tail = currP;

	/*
	* Return the pointer to where we were called
	* from.  Since we did not remove this node it
	* will be the same.
	*/
	return currP;
}

void remove_node_with_node_buf(LinkedList_t *list, node_buf_t *nb) {
	if (!list || !nb) return;
	int num_nodes_removed = 0;
	node_t *new_tail = NULL;
	list->head = remove_node_with_node_buf_internal(list->head, nb, &num_nodes_removed, &new_tail);
	if (new_tail) list->tail = new_tail;
	list->node_count = list->node_count - num_nodes_removed;
}

void free_list(LinkedList_t *list) {
	if (!list || !list->head) return;
	node_t *tmp;
	while ((tmp = list->head) != NULL) {
		list->head = list->head->next;
		free(tmp);
	}

	free(list);
}
