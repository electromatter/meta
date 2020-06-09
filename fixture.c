#include "fixture.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

extern unsigned char fixture_bootstrap[4096];

static void *rand_page(void *other)
{
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_SHARED | MAP_ANONYMOUS;
	uintptr_t rand_addr;
	void *addr;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	while (fd >= 0) {
		if (read(fd, &rand_addr, sizeof(rand_addr)) < 0)
			break;

		/* Pick a random page below the architectural hole */
		rand_addr <<= 10;
		rand_addr &= ((uintptr_t)1 << 47) - 1;

		/* Leave the bottom half of userspace for the heap */
		rand_addr |= 0x400000000000ULL;

		/* Try to keep them within 4GB of each other */
		if (other) {
			rand_addr &= 0xffffffffUL;
			rand_addr |= (uintptr_t)other & 0xffffffff00000000ULL;
			rand_addr &= ~(uintptr_t)0xfff;
		}

		addr = mmap((void *)rand_addr, PAGE_SIZE, prot, flags, -1, 0);
		if (!addr)
			break;

		if (addr == (void *)rand_addr) {
			close(fd);
			return addr;
		}

		munmap(addr, PAGE_SIZE);
	}

	/* Fall back to non random */
	if (fd >= 0)
		close(fd);
	return mmap(NULL, PAGE_SIZE, prot, flags, -1 , 0);
}

static void fixture_child(struct fixture *fix)
{
	int i;
	sigset_t set;
	void *pages[] = {fix->code, fix->data, fix->rodata};

	/* Close all files */
	for (i = 0; i < 1000; i++)
		close(i);

	/* Unblock all signals */
	for (i = 0; i < 64; i++)
		signal(i, SIG_DFL);
	sigemptyset(&set);
	if (sigprocmask(SIG_SETMASK, &set, NULL) < 0)
		abort();

	/* Copy the bootstrap before  */
	memcpy(fix->code, fixture_bootstrap, sizeof(fixture_bootstrap));

	/* code=--x, data=rw-, rodata=r-- */
	personality(0);
	if (mprotect(fix->code, PAGE_SIZE, PROT_EXEC) != 0)
		abort();
	if (fix->data && mprotect(fix->data, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0)
		abort();
	if (fix->rodata && mprotect(fix->rodata, PAGE_SIZE, PROT_READ) != 0)
		abort();

	if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
		abort();

	/* Jump to bootstrap: unmap memory and enable seccomp */
	((void (*)(void **))fix->code)(pages);
	abort();
}

void fixture_free(struct fixture *fix)
{
	sigset_t mask, saved;

	fix->ready = 0;

	if (fix->code)
		munmap(fix->code, PAGE_SIZE);
	if (fix->data)
		munmap(fix->data, PAGE_SIZE);
	if (fix->rodata)
		munmap(fix->rodata, PAGE_SIZE);
	fix->code = fix->data = fix->rodata = NULL;

	if (fix->pid >= 0) {
		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &mask, &saved);
		do {
			kill(fix->pid, SIGKILL);
			waitpid(fix->pid, NULL, 0);
		} while (errno == EINTR);
		sigprocmask(SIG_SETMASK, &saved, NULL);
	}
	fix->pid = -1;
}

struct fixture *fixture_fork(int flags)
{
	struct fixture *fix = malloc(sizeof(*fix));
	if (!fix)
		return NULL;

	fix->ready = fix->status = 0;
	fix->pid = -1;
	fix->code = fix->data = fix->rodata = NULL;

	if (!(fix->code = rand_page(NULL)))
		goto fail;
	if ((flags & FIXTURE_DATA) && !(fix->data = rand_page(fix->code)))
		goto fail;
	if ((flags & FIXTURE_RODATA) && !(fix->rodata = rand_page(fix->code)))
		goto fail;

	fix->pid = fork();
	if (fix->pid < -1) {
fail:
		fixture_free(fix);
		free(fix);
		return NULL;
	}

	if (fix->pid == 0) {
		fixture_child(fix);
		abort();
	}

	return fix;
}

int fixture_change(struct fixture *fix, pid_t pid, int status)
{
	if (pid < 0 || fix->pid != pid)
		return 0;

	fix->status = status;
	fix->ready = 0;

	if (WIFEXITED(status) || WIFSIGNALED(status))
		fix->pid = -1;

	if (!WIFSTOPPED(status))
		return 0;

	if (ptrace(PTRACE_SETOPTIONS, fix->pid, NULL, (void *)PTRACE_O_EXITKILL) < 0)
		return -1;

	/* Update process state */
	if (ptrace(PTRACE_GETSIGINFO, fix->pid, NULL, &fix->siginfo) < 0)
		return -1;
	if (ptrace(PTRACE_GETREGS, fix->pid, NULL, &fix->regs) < 0)
		return -1;
	if (ptrace(PTRACE_GETFPREGS, fix->pid, NULL, &fix->fpregs) < 0)
		return -1;

	fix->ready = 1;
	return 1;
}

int fixture_run(struct fixture *fix, const void *code, size_t size)
{
	unsigned char *ptr;

	if (size > PAGE_SIZE)
		return -1;

	if (!fix->ready)
		return 0;

	memset(fix->code, 0xcc, PAGE_SIZE);

	ptr = (unsigned char *)fix->code + PAGE_SIZE - size;
	memcpy(ptr, code, size);
	fix->regs.rip = (uintptr_t)ptr;

	if (ptrace(PTRACE_SETREGS, fix->pid, NULL, &fix->regs) < 0)
		return -1;
	if (ptrace(PTRACE_SETFPREGS, fix->pid, NULL, &fix->fpregs) < 0)
		return -1;

	if (ptrace(PTRACE_CONT, fix->pid, NULL, NULL) < 0)
		return -1;

	fix->ready = 0;
	return 1;
}
