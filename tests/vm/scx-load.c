// SPDX-License-Identifier: GPL-2.0-only
/* Loads a BPF scheduler into droidspaces_scx and keeps it for a while.
 *
 * The kernel knows sched_ext_ops only through types the module appended to
 * its vmlinux BTF at run time, which /sys/kernel/btf/vmlinux does not show.
 * The module offers the merged BTF as a file, and binding that over the
 * sysfs path in a private mount namespace lets an unmodified libbpf find the
 * type, its members and the kfuncs.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int copy(const char *from, const char *to)
{
	char buf[65536];
	int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ssize_t n;

	if (in < 0 || out < 0)
		return -1;
	while ((n = read(in, buf, sizeof(buf))) > 0)
		if (write(out, buf, n) != n)
			return -1;
	close(in);
	close(out);
	return n;
}

static int print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	return level == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	const char *merged = "/data/local/tmp/scx-merged.btf";
	struct bpf_link *link;
	int seconds;

	if (argc != 3) {
		fprintf(stderr, "usage: %s scheduler.bpf.o seconds\n", argv[0]);
		return 2;
	}
	seconds = atoi(argv[2]);
	/* Android's root is read-only, the test VM has nothing but its root. */
	if (copy("/sys/module/droidspaces_scx/btf", merged))
		merged = "/scx-merged.btf";
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
	    copy("/sys/module/droidspaces_scx/btf", merged) ||
	    mount(merged, "/sys/kernel/btf/vmlinux", NULL, MS_BIND, NULL)) {
		perror("merged BTF");
		return 1;
	}
	libbpf_set_print(print);
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "SCX-BPF load: FAIL\n");
		return 1;
	}
	printf("SCX-BPF load: PASS\n");
	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			continue;
		link = bpf_map__attach_struct_ops(map);
		if (!link) {
			fprintf(stderr, "SCX-BPF attach: FAIL\n");
			return 1;
		}
		printf("SCX-BPF attach: PASS\n");
		fflush(stdout);
		sleep(seconds);
		bpf_object__for_each_map(map, obj) {
			unsigned long vals[2] = { 0 };
			int key = 0;

			if (!strstr(bpf_map__name(map), ".bss"))
				continue;
			if (!bpf_map_lookup_elem(bpf_map__fd(map), &key, vals))
				printf("SCX-BPF nr_calls=%lu nr_cpus=%lu\n", vals[0], vals[1] & 0xffffffff);
		}
		bpf_link__destroy(link);
		printf("SCX-BPF detach: PASS\n");
		return 0;
	}
	fprintf(stderr, "no struct_ops map in %s\n", argv[1]);
	return 1;
}
