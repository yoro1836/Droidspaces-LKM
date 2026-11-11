// SPDX-License-Identifier: GPL-2.0-only
/*
 * ramplus-push: send a process's anonymous memory to Samsung RAM Plus.
 *
 * Samsung kernels with CONFIG_ZRAM_RAMPLUS write zram contents out to a file
 * on flash per process: the Android framework swaps an app out with
 * process_madvise(MADV_PAGEOUT) and then asks zram to move those swap slots
 * to the backing device with the vendor-specific MADV_WRITEBACK. It only does
 * that for Android apps. A container's processes are unknown to it, so their
 * swapped memory stays in RAM as compressed zram data.
 *
 * This does the same two calls for the PIDs given on the command line.
 *
 *   ramplus-push [-p|-w|-r] PID...
 *     (default) page out, then write back to flash
 *     -p        page out only (to zram)
 *     -w        write back only (what is already in zram)
 *     -r        prefetch: read written-back memory in again
 *
 * Needs root (CAP_SYS_NICE and ptrace access to the target).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#define DS_MADV_PAGEOUT   21
#define DS_MADV_WRITEBACK 29	/* Samsung: include/uapi/asm-generic/mman-common.h */
#define DS_MADV_PREFETCH  30
#define CHUNK (256UL << 20)

static long meminfo_kb(const char *key)
{
	char line[256];
	long value = -1;
	FILE *f = fopen("/proc/meminfo", "r");

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		if (!strncmp(line, key, strlen(key)) && line[strlen(key)] == ':')
			value = atol(line + strlen(key) + 1);
	fclose(f);
	return value;
}

/* The n-th whitespace separated number of a one-line sysfs file. */
static long long sysfs_field(const char *path, int n)
{
	char buf[512], *p = buf, *end;
	long long value = -1;
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	if (fgets(buf, sizeof(buf), f))
		for (; n >= 0; n--) {
			value = strtoll(p, &end, 10);
			if (end == p) {
				value = -1;
				break;
			}
			p = end;
		}
	fclose(f);
	return value;
}

static void rollup(int pid, long *rss, long *swap)
{
	char path[64], line[256];
	FILE *f;

	*rss = *swap = -1;
	snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
	f = fopen(path, "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Rss:", 4))
			*rss = atol(line + 4);
		else if (!strncmp(line, "Swap:", 5))
			*swap = atol(line + 5);
	}
	fclose(f);
}

/* Apply one advice to every private anonymous mapping of the process. */
static unsigned long advise(int pid, int pidfd, int behavior, int *busy)
{
	char path[64], line[512], perms[8], name[256];
	unsigned long start, end, inode, done = 0;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		name[0] = 0;
		if (sscanf(line, "%lx-%lx %7s %*x %*s %lu %255[^\n]",
			   &start, &end, perms, &inode, name) < 4)
			continue;
		if (inode || perms[1] != 'w' || perms[3] != 'p')
			continue;
		if (!strncmp(name, "[stack", 6) || !strncmp(name, "[v", 2))
			continue;
		while (start < end) {
			struct iovec iov = {
				.iov_base = (void *)start,
				.iov_len = end - start > CHUNK ? CHUNK : end - start,
			};
			long ret = syscall(__NR_process_madvise, pidfd, &iov, 1UL, behavior, 0U);

			if (ret < 0 && errno == EBUSY && *busy < 50) {
				/* Another MADV_WRITEBACK is running; only one at a time. */
				(*busy)++;
				usleep(100000);
				continue;
			}
			if (ret > 0)
				done += ret;
			start += iov.iov_len;
		}
	}
	fclose(f);
	return done;
}

int main(int argc, char **argv)
{
	int pageout = 1, writeback = 1, prefetch = 0, i = 1, busy = 0;
	long avail0 = meminfo_kb("MemAvailable");
	long long zram0 = sysfs_field("/sys/block/zram0/mm_stat", 2);
	long long bd0 = sysfs_field("/sys/block/zram0/bd_stat", 1);

	if (argc > 1 && argv[1][0] == '-') {
		if (!strcmp(argv[1], "-p"))
			writeback = 0;
		else if (!strcmp(argv[1], "-w"))
			pageout = 0;
		else if (!strcmp(argv[1], "-r"))
			pageout = writeback = 0, prefetch = 1;
		else
			argc = 1;
		i = 2;
	}
	if (i >= argc) {
		fprintf(stderr, "usage: %s [-p|-w|-r] PID...\n"
			"  default: page out, then write back to RAM Plus\n"
			"  -p page out only   -w write back only   -r prefetch\n", argv[0]);
		return 2;
	}
	for (; i < argc; i++) {
		int pid = atoi(argv[i]);
		int pidfd = syscall(__NR_pidfd_open, pid, 0U);
		long rss0, swap0, rss1, swap1;
		unsigned long out = 0, wb = 0, pf = 0;

		if (pid <= 0 || pidfd < 0) {
			fprintf(stderr, "pid %s: %s\n", argv[i], strerror(errno));
			continue;
		}
		rollup(pid, &rss0, &swap0);
		if (pageout)
			out = advise(pid, pidfd, DS_MADV_PAGEOUT, &busy);
		if (writeback) {
			errno = 0;
			wb = advise(pid, pidfd, DS_MADV_WRITEBACK, &busy);
			if (!wb && errno == EINVAL)
				fprintf(stderr, "pid %d: this kernel has no MADV_WRITEBACK\n", pid);
		}
		if (prefetch)
			pf = advise(pid, pidfd, DS_MADV_PREFETCH, &busy);
		rollup(pid, &rss1, &swap1);
		printf("pid %-7d rss %7ld -> %7ld kB  swap %7ld -> %7ld kB  (walked: pageout %lu kB, writeback %lu kB, prefetch %lu kB)\n",
		       pid, rss0, rss1, swap0, swap1, out >> 10, wb >> 10, pf >> 10);
		close(pidfd);
	}
	/* The write to flash is queued and finishes after the call returns. */
	sleep(3);
	printf("MemAvailable      %8ld -> %8ld kB\n", avail0, meminfo_kb("MemAvailable"));
	printf("zram RAM use      %8lld -> %8lld kB\n", zram0 / 1024,
	       sysfs_field("/sys/block/zram0/mm_stat", 2) / 1024);
	printf("on flash (bd_count) %6lld -> %8lld kB\n", bd0,
	       sysfs_field("/sys/block/zram0/bd_stat", 1));
	if (busy)
		printf("waited %d times for another writeback to finish\n", busy);
	return 0;
}
