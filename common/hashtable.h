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

typedef struct hash_node {
	char username[MAX_CHARS_USERNAME];
	LinkedList_t *ips;
	struct hash_node *next;
} hash_node_t;

typedef hash_node_t *hashtable_t[HASHSIZE];

#define SZ_HASH_NODE sizeof(hash_node_t)
#define SZ_HASHTBL sizeof(hashtable_t)

unsigned hash(char *s);
hash_node_t *lookup_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME]);
hash_node_t *add_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], LinkedList_t *ips);
hash_node_t *add_ip_to_user(hashtable_t *hashtbl, char username[MAX_CHARS_USERNAME], node_t *ip);
void freehashtable(hashtable_t *hashtbl);

#endif /* hashtable_h */
