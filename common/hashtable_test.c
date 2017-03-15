#include <stdio.h>
#include <string.h>

#include "hashtable.h"

hashtable_t hashtbl;

void load_hashtbl_from_db() {
	printf("lets load hashtbl 0\n");
	memset(&hashtbl, '\0', SZ_HASHTBL);
	printf("lets load hashtbl 1\n");
	add_user(&hashtbl, "waynemystir", NULL);
	printf("lets load hashtbl 2\n");
	add_user(&hashtbl, "mike_schmidt", NULL);
	add_user(&hashtbl, "pete_rose", NULL);
	add_user(&hashtbl, "julius_erving", NULL);
}

void find_some_users() {
	hash_node_t *wayne = lookup_user(&hashtbl, "waynemystir");
	printf("find_some_users waynemystir:%s\n", wayne->username);
	hash_node_t *mike_s = lookup_user(&hashtbl, "mike_schmidt");
	printf("find_some_users mike_schmidt:%s\n", mike_s->username);
	hash_node_t *pete_rose = lookup_user(&hashtbl, "pete_rose");
	printf("find_some_users pete_rose:%s\n", pete_rose->username);
	hash_node_t *julius_erving = lookup_user(&hashtbl, "julius_erving");
	printf("find_some_users julius_erving:%s\n", julius_erving->username);
}

void add_some_contacts() {

	add_contact(&hashtbl, "pete_rose", "waynemystir");
	add_contact(&hashtbl, "pete_rose", "mike_schmidt");
	add_contact(&hashtbl, "pete_rose", "pete_rose");
	add_contact(&hashtbl, "pete_rose", "julius_erving");

	add_contact(&hashtbl, "julius_erving", "waynemystir");
	add_contact(&hashtbl, "julius_erving", "waynemystir");
	add_contact(&hashtbl, "julius_erving", "pete_rose");
	add_contact(&hashtbl, "julius_erving", "mike_schmidt");
	add_contact(&hashtbl, "julius_erving", "julius_erving");

	add_contact(&hashtbl, "mike_schmidt", "waynemystir");
	add_contact(&hashtbl, "mike_schmidt", "mike_schmidt");
	add_contact(&hashtbl, "mike_schmidt", "pete_rose");
	add_contact(&hashtbl, "mike_schmidt", "julius_erving");
	
	add_contact(&hashtbl, "waynemystir", "waynemystir");
	add_contact(&hashtbl, "waynemystir", "mike_schmidt");
	add_contact(&hashtbl, "waynemystir", "pete_rose");
	add_contact(&hashtbl, "waynemystir", "julius_erving");
}

void read_some_contacts() {
	hash_node_t *wayne = lookup_user(&hashtbl, "waynemystir");
	contact_list_t *waynes_contacts = wayne->contacts;
	contact_t *c = NULL;
	c = waynes_contacts->head;
	while (c) {
		printf("waynes_contact:%s\n", c->hn->username);
		c = c->next;
	}

	hash_node_t *julius = lookup_user(&hashtbl, "julius_erving");
	contact_list_t *julius_contacts = julius->contacts;
	c = julius_contacts->head;
	while (c) {
		printf("julius'_contact:%s\n", c->hn->username);
		c = c->next;
	}

	hash_node_t *mike = lookup_user(&hashtbl, "mike_schmidt");
	contact_list_t *mikes_contacts = mike->contacts;
	c = mikes_contacts->head;
	while (c) {
		printf("mikes_contact:%s\n", c->hn->username);
		c = c->next;
	}

	hash_node_t *pete = lookup_user(&hashtbl, "pete_rose");
	contact_list_t *petes_contacts = pete->contacts;
	c = petes_contacts->head;
	while (c) {
		printf("petes_contact:%s\n", c->hn->username);
		c = c->next;
	}
}

int main() {
	printf("hashtable_test main 0 szhn:%lu szct:%lu\n", SZ_HASH_NODE, SZ_CONTACT);
	load_hashtbl_from_db();
	find_some_users();
	add_some_contacts();
	read_some_contacts();
	freehashtable(&hashtbl);
	return 0;
}