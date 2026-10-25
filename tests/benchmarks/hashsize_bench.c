/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *path = "/proc/sys/net/netflow/hashsize";
static int original, changed;

static double seconds(clockid_t clock)
{
	struct timespec ts;

	if (clock_gettime(clock, &ts))
		exit(2);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int put(int size, int empty)
{
	char buffer[32];
	int length = empty ? 0 : snprintf(buffer, sizeof(buffer), "%d\n", size);
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t ret;
	int saved;

	if (fd < 0)
		return -1;
	ret = write(fd, buffer, length);
	saved = errno;
	close(fd);
	errno = saved;
	return ret == length ? 0 : -1;
}

static void restore(void)
{
	if (changed && put(original, 0))
		perror("RESTORE HASH SIZE FAILED");
}

int main(int argc, char **argv)
{
	FILE *file;
	int i;

	if (argc != 2 || (strcmp(argv[1], "noop") && strcmp(argv[1], "empty") &&
			  strcmp(argv[1], "resize")))
		return 2;
	file = fopen(path, "r");
	if (!file || fscanf(file, "%d", &original) != 1)
		return 2;
	fclose(file);
	if (original < 256 || original > 10000000)
		return 2;
	atexit(restore);
	for (i = 0; i < 3; i++) {
		double wall = seconds(CLOCK_MONOTONIC);
		double cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
		int rc;

		if (!strcmp(argv[1], "resize")) {
			changed = 1;
			rc = put(original + 256, 0);
			if (!rc)
				rc = put(original, 0);
			if (!rc)
				changed = 0;
		} else {
			rc = put(original, !strcmp(argv[1], "empty"));
		}
		if (rc) {
			perror("hashsize write");
			return 1;
		}
		printf("{\"operation\":\"%s\",\"iteration\":%d,"
		       "\"wall_ms\":%.6f,\"cpu_ms\":%.6f}\n",
		       argv[1], i + 1, (seconds(CLOCK_MONOTONIC) - wall) * 1000,
		       (seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu) * 1000);
	}
	return 0;
}
