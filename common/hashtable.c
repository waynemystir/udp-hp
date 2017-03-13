#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

unsigned hash(char *s) {
	unsigned hashval;
	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;
	return hashval % HASHSIZE;
}

hash_node_t *lookup(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]) {
	if (!hashtbl) return NULL;
	hash_node_t *np;
	for (np = (*hashtbl)[hash(username)]; np != NULL; np = np->next)
		if (strcmp(username, np->username) == 0)
			return np; /* found */
	return NULL; /* not found */
}

hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], LinkedList_t *ips) {
	if (!hashtbl) return NULL;
	hash_node_t *np;
	unsigned hashval;
	if ((np = lookup(hashtbl, username)) == NULL) { /* not found */
		np = malloc(SZ_HASH_NODE);
		if (np == NULL) return NULL;
		strcpy(np->username, username);
		hashval = hash(username);
		np->next = (*hashtbl)[hashval];
		(*hashtbl)[hashval] = np;
	}

	memcpy(np->ips, ips, SZ_LINK_LIST);
	return np;
}

hash_node_t *add_ip_to_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], node_t *ip) {
	return NULL;
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
			free_list(tmp->ips);
			free(tmp);
		}
	}
}