// Minimal UDP flood for the drop-cost experiments: sendmmsg() batches of 64 packets
// to DST:PORT for SECONDS, from a given source address. Prints packets sent.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "usage: %s SRC DST PORT SECONDS [PAYLOAD]\n", argv[0]);
		return 2;
	}
	int payload = argc > 5 ? atoi(argv[5]) : 18; /* 18 B payload -> 64 B Ethernet frame */
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in src = {.sin_family = AF_INET}, dst = {.sin_family = AF_INET};
	inet_pton(AF_INET, argv[1], &src.sin_addr);
	inet_pton(AF_INET, argv[2], &dst.sin_addr);
	dst.sin_port = htons(atoi(argv[3]));
	if (bind(fd, (struct sockaddr *)&src, sizeof(src)) || connect(fd, (struct sockaddr *)&dst, sizeof(dst))) {
		perror("socket");
		return 1;
	}
	char buf[1500] = {0};
	struct iovec iov = {.iov_base = buf, .iov_len = payload};
	struct mmsghdr msgs[BATCH];
	memset(msgs, 0, sizeof(msgs));
	for (int i = 0; i < BATCH; i++) {
		msgs[i].msg_hdr.msg_iov = &iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	double limit = atof(argv[4]);
	unsigned long long sent = 0;
	for (;;) {
		int n = sendmmsg(fd, msgs, BATCH, 0);
		if (n > 0)
			sent += n;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9 >= limit)
			break;
	}
	printf("%llu\n", sent);
	return 0;
}
