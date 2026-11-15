// SPDX-License-Identifier: GPL-2.0-only
/* Exercises a task that sits in the ext class: every way the scheduler core
 * can touch it while it runs, sleeps, moves or leaves.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PARAMS "/sys/module/droidspaces_scx/parameters/"

static int param(const char *name, int pid)
{
	char path[128], buf[16];
	int fd, n, ret;

	snprintf(path, sizeof(path), PARAMS "%s", name);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	n = snprintf(buf, sizeof(buf), "%d", pid);
	ret = write(fd, buf, n) == n ? 0 : -errno;
	close(fd);
	return ret;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double cpu_time(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void spin(double seconds)
{
	double end = now() + seconds;

	while (now() < end)
		;
}

#define CHECK(cond, what) do { \
	if (!(cond)) { printf("SCX %s: FAIL\n", what); exit(1); } \
	printf("SCX %s: PASS\n", what); fflush(stdout); } while (0)

int main(void)
{
	struct sched_param fifo = { .sched_priority = 1 }, other = { 0 };
	int a[2], b[2], i, status;
	cpu_set_t set;
	double before;
	pid_t child;
	char c = 0;

	CHECK(param("attach", getpid()) == 0, "attach");
	CHECK(param("attach", getpid()) == -EINVAL, "attach twice is refused");

	before = cpu_time();
	spin(1);
	CHECK(cpu_time() - before > 0.1, "runs and is accounted");

	for (i = 0; i < 300; i++)
		sched_yield();
	CHECK(1, "yield");

	for (i = 0; i < 200; i++) {
		setpriority(PRIO_PROCESS, 0, i % 20);
		CPU_ZERO(&set);
		CPU_SET(i % 2, &set);
		sched_setaffinity(0, sizeof(set), &set);
		spin(0.002);
	}
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	CPU_SET(1, &set);
	sched_setaffinity(0, sizeof(set), &set);
	CHECK(1, "nice and affinity changes");

	/* Wake each other across a pipe pair, both in the class. */
	if (pipe(a) || pipe(b))
		return 1;
	child = fork();
	if (!child) {
		if (param("attach", getpid()))
			_exit(2);
		for (i = 0; i < 300; i++)
			if (read(a[0], &c, 1) != 1 || write(b[1], &c, 1) != 1)
				_exit(3);
		_exit(0);
	}
	for (i = 0; i < 300; i++)
		if (write(a[1], &c, 1) != 1 || read(b[0], &c, 1) != 1)
			break;
	waitpid(child, &status, 0);
	CHECK(i == 300 && WIFEXITED(status) && !WEXITSTATUS(status), "sleep and wake, exit while attached");

	/* Killed while runnable and while asleep. */
	for (i = 0; i < 20; i++) {
		child = fork();
		if (!child) {
			param("attach", getpid());
			if (i & 1)
				pause();
			for (;;)
				;
		}
		usleep(20000);
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
	}
	CHECK(1, "killed while attached");

	/* The core moves it to rt and back to fair by itself: it is then out. */
	CHECK(sched_setscheduler(0, SCHED_FIFO, &fifo) == 0, "to fifo");
	spin(0.05);
	CHECK(sched_setscheduler(0, SCHED_OTHER, &other) == 0, "back to other");
	spin(0.05);
	CHECK(param("detach", getpid()) == -EINVAL, "left the class through fifo");
	CHECK(param("attach", getpid()) == 0, "attach again");
	spin(0.2);
	CHECK(param("detach", getpid()) == 0, "detach");
	before = cpu_time();
	spin(0.5);
	CHECK(cpu_time() - before > 0.1, "runs as fair again");
	return 0;
}
