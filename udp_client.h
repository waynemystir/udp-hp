//
//  udp_client.h
//  udp-hole-punch
//
//  Created by WAYNE SMALL on 2/19/17.
//  Copyright © 2017 Waynemystir. All rights reserved.
//

#ifndef udp_client_h
#define udp_client_h

#include "network_utils.h"

int wain(void (*self_info)(char *),
		void (*server_info)(char *),
		void (*socket_created)(int sock_fd),
		void (*socket_bound)(void),
		void (*sendto_succeeded)(size_t bytes_sent),
		void (*recd)(size_t bytes_recd, socklen_t addr_len, char *),
		void (*coll_buf)(char *),
		void (*new_client)(char *),
		void (*confirmed_client)(void),
		void (*new_peer)(char *),
		void (*unhandled_response_from_server)(int),
		void (*chat_socket_created)(int),
		void (*chat_socket_bound)(void),
		void (*chat_sendto_succeeded)(size_t),
		void (*chat_recd)(size_t, socklen_t, char *),
		void (*whilew)(int),
		void (*end_while)(void));

void ping_all_peers();

int send_message_to_peer(char *);

#endif /* udp_client_h */
