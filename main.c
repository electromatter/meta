#include "fixture.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>

static const unsigned char code[] = {
	0x90,
};

int main(int argc, char **argv)
{
	pid_t pid;
	int status, ret;
	struct fixture *fix = fixture_fork();
	if (!fix)
		return 1;

	while (1) {
		pid = wait(&status);
		if (pid < 0 && errno == ECHILD)
			break;

		ret = fixture_change(fix, pid, status);
		if (ret < 0) {
			fixture_free(fix);
			return 1;
		}

		printf("WAIT: pid=%d sig=%d ptr=%p lower=%p upper=%p\n", pid, WSTOPSIG(status), fix->siginfo.si_addr, fix->siginfo.si_lower, fix->siginfo.si_upper);

		if (ret > 0) {
			fixture_run(fix, code, sizeof(code));
		}
	}

	fixture_free(fix);
	return 0;
}
