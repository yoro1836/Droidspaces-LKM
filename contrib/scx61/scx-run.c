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
 *
 * The Rust schedulers also keep a socket in /var/run/scx, and Android's root
 * is read-only and has no /var. Then the namespace gets a root of its own: a
 * tmpfs with the real top-level directories bound into it, plus /var/run.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
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

static int new_root(void)
{
	const char *root = "/dev/scx-root";
	char from[PATH_MAX], to[PATH_MAX], target[PATH_MAX], cwd[PATH_MAX];
	struct dirent *e;
	struct stat st;
	ssize_t n;
	DIR *d;

	if (!getcwd(cwd, sizeof(cwd)) || (mkdir(root, 0700) && errno != EEXIST) ||
	    mount("tmpfs", root, "tmpfs", 0, "mode=755") || !(d = opendir("/")))
		return -1;
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(from, sizeof(from), "/%s", e->d_name);
		snprintf(to, sizeof(to), "%s/%s", root, e->d_name);
		if (lstat(from, &st))
			continue;
		if (S_ISLNK(st.st_mode)) {
			n = readlink(from, target, sizeof(target) - 1);
			/* a link missing from the new root fails the access to it only */
			if (n >= 0 && (target[n] = 0, symlink(target, to)))
				continue;
		} else if (S_ISDIR(st.st_mode)) {
			if (!mkdir(to, 0755))
				mount(from, to, NULL, MS_BIND | MS_REC, NULL);
		} else {
			close(open(to, O_WRONLY | O_CREAT, 0600));
			mount(from, to, NULL, MS_BIND, NULL);
		}
	}
	closedir(d);
	snprintf(to, sizeof(to), "%s/var", root);
	mkdir(to, 0755);
	snprintf(to, sizeof(to), "%s/var/run", root);
	if (mkdir(to, 0755) || chroot(root))
		return -1;
	return chdir(cwd);
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
	if (access("/var/run", F_OK) && new_root()) {
		perror("scx-run: /var/run");
		return 1;
	}
	execvp(argv[1], argv + 1);
	perror(argv[1]);
	return 1;
}
