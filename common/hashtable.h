//
//  common.h
//  udp-hp
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef hashtable_h
#define hashtable_h

#include "node.h"

#define HASHSIZE 40001

struct hash_node;

typedef struct contact {
	struct hash_node *hn;
	struct contact *next;
} contact_t;

typedef struct contact_list {
	contact_t *head;
	contact_t *tail;
	unsigned int count;
} contact_list_t;

typedef struct hash_node {
	char username[MAX_CHARS_USERNAME];
	LinkedList_t *nodes;
	contact_list_t *contacts;
	struct hash_node *next;
} hash_node_t;

typedef struct hash_node_list {
	hash_node_t *head;
	hash_node_t *tail;
	unsigned int count;
} hash_node_list_t;

typedef hash_node_t *hashtable_t[HASHSIZE];

#define SZ_HASH_NODE sizeof(hash_node_t)
#define SZ_CONTACT sizeof(contact_t)
#define SZ_CONTACT_LIST sizeof(contact_list_t)
#define SZ_HASHTBL sizeof(hashtable_t)

unsigned hash(char *s);
hash_node_t *lookup_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]);
// void username_from_id(ID id, char username[MAX_CHARS_USERNAME]);
// void id_from_username(char username[MAX_CHARS_USERNAME], ID id);
hash_node_t *lookup_user_from_id(hashtable_t *hashtbl, char id[MAX_CHARS_USERNAME]);
hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]);
hash_node_t *add_ip_to_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], node_t *ip);
void add_contact(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], char contactname[MAX_CHARS_USERNAME]);
contact_t *lookup_contact(contact_list_t *cl, char contactname[MAX_CHARS_USERNAME]);
contact_t *lookup_contact_and_node_from_node_buf(contact_list_t *cl, node_buf_t *nb, node_t **contact_node);
contact_t *lookup_contact_and_node_from_sockaddr(contact_list_t *cl, struct sockaddr *addr, SERVER_TYPE st, node_t **contact_node);
void add_node_to_contacts(hash_node_t *hn, node_buf_t *nb, node_t **new_node);
void contacts_perform(contact_list_t *contacts, void (*perform)(contact_t *contact, void *arg), void *arg);
void freehashtable(hashtable_t *hashtbl);

#endif /* hashtable_h */
