// SPDX-License-Identifier: GPL-2.0-only
/* Loads a scheduler's BPF object without attaching it, to see what the
 * verifier of the running kernel says about it:
 *
 *   scx-run scx-probe scheduler.bpf.o
 *
 * A scheduler's own loader sets up its read-only data first, so a pass here
 * says that the programs verify with the defaults, not that it will run.
 */
#include <bpf/libbpf.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj;

	if (argc != 2) {
		fprintf(stderr, "usage: %s scheduler.bpf.o\n", argv[0]);
		return 2;
	}
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || bpf_object__load(obj)) {
		printf("PROBE %s: rejected\n", argv[1]);
		return 1;
	}
	printf("PROBE %s: verified\n", argv[1]);
	return 0;
}
