#include <stdio.h>

#include "udp_client.h"

void self_info(char *w, unsigned short port, unsigned short chat_port, unsigned short family) {
	char e[256];
	sprintf(e, "self: %s p:%d cp:%d f:%d", w, port, chat_port, family);
	printf("%s\n", e);
}

void server_info(char *w) {
	printf("%s\n", w);
}

void socket_created(int sock_fd) {
	char w[256];
	sprintf(w, "The socket file descriptor is %d", sock_fd);
	printf("%s\n", w);
}

void socket_bound(void) {
	char *w = "The socket was bound";
	printf("%s\n", w);
}

void sendto_succeeded(size_t bytes_sent) {
	char w[256];
	sprintf(w, "sendto succeeded, %zu bytes sent", bytes_sent);
	printf("%s\n", w);
}

void recd(size_t bytes_recd, socklen_t addr_len, char *w) {
	char e[256];
	sprintf(e, "recvfrom %zu %u %s", bytes_recd, addr_len, w);
	printf("%s\n", e);
}

void coll_buf(char *w) {
	printf("%s\n", w);
}

void new_client(SERVER_TYPE st, char *w) {
    char st_str[15];
    str_from_server_type(st, st_str);
    printf("%s %s\n", st_str, w);
}

void stay_touch_recd(SERVER_TYPE st) {
    char st_str[15];
    str_from_server_type(st, st_str);
    char w[256];
    sprintf(w, "stay_touch_recd %s", st_str);
    printf("%s\n", w);
}

void confirmed_client() {
	char *w = "Confirmed client\n";
	printf("%s\n", w);
}

void new_peer(char *w) {
	printf("%s\n", w);
}

void hole_punch_sent(char *w, int t) {
	char wc [256];
	sprintf(wc, "%s count %d", w, t);
	printf("%s\n", wc);
}

void confirmed_peer_while_punching(void) {
	char w[] = "*$*$*$*$*$*$*$*$*$*$*$*$* CPWP";
	printf("%s\n", w);
}

void from_peer(char *w) {
    printf("%s\n", w);
}

void unhandled_response_from_server(int w) {
	char wc [100];
	sprintf(wc, "unhandled_response_from_server::%d", w);
	printf("%s", wc);
}

void whilew(int w) {
	char wt[256];
	sprintf(wt, "Meanwhile...%d\n", w);
	printf("%s", wt);
}

void end_while(void) {
	char *w = "Ending while looping***************\n";
	printf("%s", w);
}

int main() {
	printf("udp_client_test main 0\n");
	wain(self_info,
		server_info,
		socket_created,
		socket_bound,
		sendto_succeeded,
		recd,
		coll_buf,
		new_client,
		confirmed_client,
		stay_touch_recd,
		new_peer,
		hole_punch_sent,
		confirmed_peer_while_punching,
		from_peer,
		unhandled_response_from_server,
		whilew,
		end_while);
	return 0;
}