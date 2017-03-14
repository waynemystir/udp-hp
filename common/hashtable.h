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
#define MAX_CHARS_USERNAME 47

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
	LinkedList_t *ips;
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
hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], LinkedList_t *ips);
hash_node_t *add_ip_to_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], node_t *ip);
void add_contact(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], char contactname[MAX_CHARS_USERNAME]);
void freehashtable(hashtable_t *hashtbl);

#endif /* hashtable_h */
