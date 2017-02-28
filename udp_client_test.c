#include <stdio.h>

#include "udp_client.h"

void self_info(char *w) {
	printf("%s\n", w);
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

void new_client(char *w) {
	printf("%s\n", w);
}

void confirmed_client() {
	char *w = "Confirmed client\n";
	printf("%s\n", w);
}

void new_peer(char *w) {
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
		new_peer,
		unhandled_response_from_server,
		whilew,
		end_while);
	return 0;
}