// SPDX-License-Identifier: GPL-2.0-only
/* Runs an unmodified sched_ext scheduler binary against droidspaces_scx:
 *
 *   scx-run scx_simple [args]
 *
 * The kernel knows sched_ext only through types the module appended to its
 * vmlinux BTF at run time, which /sys/kernel/btf/vmlinux does not show. The
 * module offers the merged BTF as a file. This binds it over the sysfs path
 * in a mount namespace of its own and then becomes the scheduler, so nothing
 * else on the system sees a changed file.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
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

int main(int argc, char **argv)
{
	/* Android's root is read-only, a bare initramfs has nothing but its root. */
	const char *merged = "/data/local/tmp/scx-merged.btf";

	if (argc < 2) {
		fprintf(stderr, "usage: %s scheduler [args]\n", argv[0]);
		return 2;
	}
	if (copy("/sys/module/droidspaces_scx/btf", merged))
		merged = "/scx-merged.btf";
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
	    copy("/sys/module/droidspaces_scx/btf", merged) ||
	    mount(merged, "/sys/kernel/btf/vmlinux", NULL, MS_BIND, NULL)) {
		perror("scx-run: merged BTF");
		return 1;
	}
	execvp(argv[1], argv + 1);
	perror(argv[1]);
	return 1;
}
