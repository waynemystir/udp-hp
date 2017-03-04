#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "node.h"

void print_node(node_t *node) {
	printf("pn %s\n", node->ip6);
}

int main() {
	printf("node_test main 0\n");

	LinkedList *list = malloc(sizeof(struct LinkedList));
	memset(list, '\0', sizeof(LinkedList));
	size_t mcip6 = 16;

	node_t n1;
	memcpy(&n1.ip6, "john", mcip6);
	node_t *p1;
	copy_and_add_tail(list, &n1, &p1);
	nodes_perform(list, print_node);
	printf("h:%s p1:%s t:%s done\n\n", list->head->ip6, p1->ip6, list->tail->ip6);

	node_t n2;
	memcpy(&n2.ip6, "lois", mcip6);
	node_t *p2;
	copy_and_add_tail(list, &n2, &p2);
	nodes_perform(list, print_node);
	printf("h:%s p2:%s t:%s done\n\n", list->head->ip6, p2->ip6, list->tail->ip6);

	node_t n3;
	memcpy(&n3.ip6, "mike", mcip6);
	node_t *p3;
	copy_and_add_tail(list, &n3, &p3);
	nodes_perform(list, print_node);
	printf("h:%s p3:%s t:%s done\n\n", list->head->ip6, p3->ip6, list->tail->ip6);

	node_t *p6;
	get_new_tail(list, &p6);
	memcpy(p6->ip6, "mary", mcip6);
	nodes_perform(list, print_node);
	printf("h:%s p6:%s t:%s done\n\n", list->head->ip6, p6->ip6, list->tail->ip6);

	node_t n4;
	memcpy(&n4.ip6, "pete", mcip6);
	node_t *p4;
	copy_and_add_tail(list, &n4, &p4);
	nodes_perform(list, print_node);
	printf("h:%s p4:%s t:%s done\n\n", list->head->ip6, p4->ip6, list->tail->ip6);

	node_t n5;
	memcpy(&n5.ip6, "abby", mcip6);
	node_t *p5;
	copy_and_add_tail(list, &n5, &p5);
	nodes_perform(list, print_node);
	printf("h:%s p5:%s t:%s done\n\n", list->head->ip6, p5->ip6, list->tail->ip6);

	free_list(list);

	return 0;
}