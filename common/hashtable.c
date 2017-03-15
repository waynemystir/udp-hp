#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

unsigned hash(char *s) {
	unsigned hashval;
	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;
	return hashval % HASHSIZE;
}

int hash_nodes_equal(hash_node_t *h1, hash_node_t *h2) {
	if (!h1 || !h2) return 0;
	return strcmp(h1->username, h2->username) == 0;
}

int hash_node_in_contacts_list(hash_node_t *hn, contact_list_t *cl) {
	if (!hn || !cl) return 0;
	contact_t *c = cl->head;
	while (c) {
		if (hash_nodes_equal(hn, c->hn)) return 1;
		c = c->next;
	}
	return 0;
}

hash_node_t *lookup_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]) {
	if (!hashtbl) return NULL;
	hash_node_t *np;
	for (np = (*hashtbl)[hash(username)]; np != NULL; np = np->next)
		if (strcmp(username, np->username) == 0)
			return np; /* found */
	return NULL; /* not found */
}

void username_from_id(ID id, char username[MAX_CHARS_USERNAME]) {
	strcpy(username, id);
}

hash_node_t *lookup_user_from_id(hashtable_t *hashtbl, ID id) {
	char username[MAX_CHARS_USERNAME];
	username_from_id(id, username);
	return lookup_user(hashtbl, username);
}

hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]) {
	if (!hashtbl) return NULL;
	hash_node_t *np;
	unsigned hashval;
	if ((np = lookup_user(hashtbl, username)) == NULL) { /* not found */
		np = malloc(SZ_HASH_NODE);
		memset(np, '\0', SZ_HASH_NODE);
		if (np == NULL) return NULL;
		strcpy(np->username, username);
		hashval = hash(username);
		np->next = (*hashtbl)[hashval];
		(*hashtbl)[hashval] = np;
		contact_list_t *contacts = malloc(SZ_CONTACT_LIST);
		memset(contacts, '\0', SZ_CONTACT_LIST);
		np->contacts = contacts;
	}

	// TODO what should we do if lookup_user returns non-NULL?
	return np;
}

void add_contact(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], char contactname[MAX_CHARS_USERNAME]) {
	printf("lets add contact %s to user %s\n", contactname, username);
	if (!hashtbl) return;
	hash_node_t *user = lookup_user(hashtbl, username);
	if (!user) return;
	hash_node_t *contact_hn = lookup_user(hashtbl, contactname);
	if (!contact_hn) return;
	if (strcmp(user->username, contact_hn->username) == 0) {
		printf("Failed attempt to add contact %s to user %s\n", contact_hn->username, user->username);
		return;
	}
	if (hash_node_in_contacts_list(contact_hn, user->contacts)) {
		printf("Not adding contact %s to contacts list. It already exists.\n", contact_hn->username);
		return;
	}

	contact_t *new_contact = malloc(SZ_CONTACT);
	memset(new_contact, '\0', SZ_CONTACT);
	new_contact->hn = contact_hn;

	if (!user->contacts->head) {
		user->contacts->head = new_contact;
		user->contacts->tail = new_contact;
	} else {
		user->contacts->tail->next = new_contact;
		user->contacts->tail = new_contact;
	}
}

void contacts_perform(contact_list_t *contacts, void (*perform)(contact_t *contact, void *arg), void *arg) {
	if (!contacts || !perform) return;
	contact_t *c = contacts->head;
	while (c) {
		perform(c, arg);
		c = c->next;
	}
}

hash_node_t *add_ip_to_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], node_t *ip) {
	return NULL;
}

void freecontacts(contact_list_t *contacts) {
	if (!contacts || !contacts->head) return;
	contact_t *c;
	while ((c = contacts->head) != NULL) {
		contacts->head = contacts->head->next;
		free(c);
	}
	free(contacts);
}

void freehashtable(hashtable_t *hashtbl) {
	if (!hashtbl) return;
	hash_node_t *htn = NULL;
	for (int j = 0; j < HASHSIZE; j++) {
		htn = (*hashtbl)[j];
		if (!htn) continue;
		hash_node_t *tmp;
		while ((tmp = htn) != NULL) {
			htn = htn->next;
			free_list(tmp->nodes);
			freecontacts(tmp->contacts);
			free(tmp);
		}
	}
}