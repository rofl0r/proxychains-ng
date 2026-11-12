/*
 * a proxified connect() must not change the file descriptor flags of the
 * socket: if FD_CLOEXEC gets lost, the connection leaks into every program
 * the application executes.
 *
 *     proxychains4 ./test_cloexec ip port
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static int check(const struct sockaddr_in *a, int fdflags) {
	int sock, got;

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	fcntl(sock, F_SETFD, fdflags);
	if(connect(sock, (const struct sockaddr *)a, sizeof(*a)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}
	got = fcntl(sock, F_GETFD);
	printf("FD_CLOEXEC before connect: %d, after: %d\n",
	       !!(fdflags & FD_CLOEXEC), !!(got & FD_CLOEXEC));
	close(sock);
	return got == fdflags;
}

int main(int argc, char *argv[]) {
	struct sockaddr_in a = { .sin_family = AF_INET };
	int ok;

	if(argc < 3 || inet_pton(AF_INET, argv[1], &a.sin_addr) != 1) {
		printf("Usage: %s ip port\n", argv[0]);
		return EXIT_FAILURE;
	}
	a.sin_port = htons(atoi(argv[2]));

	ok = check(&a, 0);
	ok &= check(&a, FD_CLOEXEC);
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
