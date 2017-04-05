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

hash_node_t *search_for_user(hashtable_t *hashtbl, char *search_text, int *number_of_results) {
	// TODO
	hash_node_t joe_doe = {0};
	strcpy(joe_doe.username, "joe_doe");
	hash_node_t phil_conners = {0};
	strcpy(phil_conners.username, "phil_conners");
	hash_node_t search_results[2] = {joe_doe, phil_conners};
	hash_node_t *sr = malloc(sizeof(search_results));
	memcpy(sr, search_results, sizeof(search_results));
	if (number_of_results) *number_of_results = 2;
	return sr;
}

// void username_from_id(ID id, char username[MAX_CHARS_USERNAME]) {
// 	strcpy(username, id);
// }

// void id_from_username(char username[MAX_CHARS_USERNAME], ID id) {
// 	strcpy(id, username);
// }

hash_node_t *lookup_user_from_id(hashtable_t *hashtbl, char id[MAX_CHARS_USERNAME]) {
	// TODO get rid of this method and use lookup_user instead
//	char username[MAX_CHARS_USERNAME];
//	username_from_id(id, username);
	return lookup_user(hashtbl, id);
}

hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], char *password) {
	if (!hashtbl) return NULL;
	hash_node_t *np;
	unsigned hashval;
	if ((np = lookup_user(hashtbl, username)) == NULL) { /* not found */
		np = malloc(SZ_HASH_NODE);
		memset(np, '\0', SZ_HASH_NODE);
		if (np == NULL) return NULL;
		strcpy(np->username, username);
		strcpy(np->password, password);
		hashval = hash(username);
		np->next = (*hashtbl)[hashval];
		(*hashtbl)[hashval] = np;
		contact_list_t *contacts = malloc(SZ_CONTACT_LIST);
		memset(contacts, '\0', SZ_CONTACT_LIST);
		np->contacts = contacts;
		LinkedList_t *nodes = malloc(SZ_LINK_LIST);
		memset(nodes, '\0', SZ_LINK_LIST);
		np->nodes = nodes;
	}

	// TODO what should we do if lookup_user returns non-NULL?
	return np;
}

contact_t *add_contact_to_list(contact_list_t *contacts, char contactname[MAX_CHARS_USERNAME]) {
	if (!contacts) return NULL;
	contact_t *ec;
	if ((ec = lookup_contact(contacts, contactname)) != NULL) return ec;
	contact_t *new_contact = malloc(SZ_CONTACT);
	memset(new_contact, '\0', SZ_CONTACT);
	new_contact->hn = malloc(SZ_HASH_NODE);
	strcpy(new_contact->hn->username, contactname);
	new_contact->hn->nodes = malloc(SZ_NODE);

	if (!contacts->head) {
		contacts->head = new_contact;
		contacts->tail = new_contact;
	} else {
		new_contact->next = contacts->head;
		contacts->head = new_contact;
	}
	contacts->count++;
	return new_contact;
}

void add_contact_to_hashtbl(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], char contactname[MAX_CHARS_USERNAME]) {
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

contact_t *lookup_contact(contact_list_t *cl, char contactname[MAX_CHARS_USERNAME]) {
	if (!cl) return NULL;
	contact_t *c = cl->head;
	while (c) {
		if (c->hn && (strcmp(c->hn->username, contactname) == 0)) return c;
		c = c->next;
	}
	return NULL;
}

contact_t *lookup_contact_and_node_from_node_buf(contact_list_t *cl, node_buf_t *nb, node_t **contact_node) {
	if (!nb) return NULL;
	contact_t *contact = lookup_contact(cl, nb->id);
	if (!contact) return NULL;
	if (!contact_node) return contact;

	node_t *cn = contact->hn->nodes->head;
	while (cn) {
		if (node_and_node_buf_equal(cn, nb)) {
			*contact_node = cn;
			break;
		}
		cn = cn->next;
	}

	return contact;
}

contact_t *lookup_contact_and_node_from_sockaddr(contact_list_t *cl, struct sockaddr *addr, SERVER_TYPE st, node_t **contact_node) {
	if (!cl || !addr) return NULL;
	node_t *n;
	contact_t *c = cl->head;
	while (c) {
		n = find_node_from_sockaddr(c->hn->nodes, addr, st);
		if (n) {
			if (contact_node) *contact_node = n;
			return c; 
		}
		c = c->next;
	}

	return NULL;
}

void add_node_to_contacts(hash_node_t *hn, node_buf_t *nb, node_t **new_node) {
	if (!hn || !nb) return;

	node_t *nn;
	node_buf_to_node(nb, &nn);
	if (!nn) return;
	if (new_node) *new_node = nn;
	contact_t *contact = add_contact_to_list(hn->contacts, nb->id);
	if (!contact) return;
	nn->next = NULL;

	if (!contact->hn->nodes->head) {
		contact->hn->nodes->head = nn;
		contact->hn->nodes->tail = nn;
	} else {
		nn->next = contact->hn->nodes->head;
		contact->hn->nodes->head = nn;
	}
	contact->hn->nodes->node_count++;
}

void contacts_perform(contact_list_t *contacts,
		void (*perform)(contact_t *contact, void *arg1, void *arg2, void *arg3),
		void *arg1,
		void *arg2,
		void *arg3) {
	if (!contacts || !perform) return;
	contact_t *c = contacts->head;
	while (c) {
		perform(c, arg1, arg2, arg3);
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
