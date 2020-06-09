#ifndef FIXTURE_H
#define FIXTURE_H

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/user.h>
#include <signal.h>
#include <stdlib.h>

struct fixture {
	int status, ready;
	pid_t pid;

	siginfo_t siginfo;
	struct user_regs_struct regs;
	struct user_fpregs_struct fpregs;

	void *code, *data, *rodata;
};

#define FIXTURE_DATA	1
#define FIXTURE_RODATA	2

/*
 * Fork a new fixture.
 *
 * Returns NULL on error
 */
extern struct fixture *fixture_fork(int flags);

/*
 * Free and kill the fixture.
 *
 * If the fixture is in a broken state (forever uninterruptable sleep),
 * this will block forever. If that is a concern, kill the pid yourself
 * and only call this when the subprocess exits.
 */
extern void fixture_free(struct fixture *fix);

/*
 * Notify fixture state change from wait.
 *
 * Returns:
 * -1  on error
 *  0  fixture is not ready
 *  1  fixture is ready
 */
extern int fixture_change(struct fixture *fix, pid_t pid, int status);

/*
 * Run the code inside the fixture.
 *
 * Returns:
 * -1  on error
 *  0  fixture is not ready
 *  1  code was submitted
 */
extern int fixture_run(struct fixture *fix, const void *code, size_t size);

#endif
