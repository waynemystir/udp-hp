#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

pthread_t chat_thread;

void *chat_endpoint(void *msg) {
	printf("chat_endpoint %s", (char *)msg);

	pthread_exit("chat_hp_thread exiting normally");
}

int main() {
	printf("chat_hp_endpoint main 0\n");
	char *thread_exit_msg;
	int pcr = pthread_create(&chat_thread, NULL, chat_endpoint, (void *)"chap_hp_thread");
	if (pcr) {
		printf("ERROR starting chat_hp_thread: %d\n", pcr);
		exit(-1);
	} else {
		pthread_join(chat_thread,(void**)&thread_exit_msg);
	}

	printf("Wrapping up chat_service: %s\n", thread_exit_msg);
	return 0;
}