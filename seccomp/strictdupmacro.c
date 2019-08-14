#define _GNU_SOURCE
#include <stddef.h> // offsetof
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h> // arch
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h> // syscall numbers
#include "seccomp_utils.h"

/* This filter allows the same system calls as the strict mode 
 * plus dup(STODUT_FILENO) call. It's written using macros defined
 * in seccomp_utils.h */
struct sock_filter  bpfcode[] = {

	/* verify the architecture */
	VERIFY_ARCHITECTURE(AUDIT_ARCH_X86_64),
	/* load syscall number in the accumulator */
	LOAD_SYSCALL_NUMBER,
	/* check if the syscall number is allowed */
	/* _exit */
	ALLOW_SYSCALL(exit),
	/* exit_group */
	ALLOW_SYSCALL(exit_group),
	/* write */
	ALLOW_SYSCALL(write),
	/* read */
	ALLOW_SYSCALL(read),
	/* sigreturn */
	ALLOW_SYSCALL(rt_sigreturn),
	/* dup(STDOUT_FILENO) */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup, 0, 3), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,(offsetof (struct seccomp_data, args[0]))),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, STDOUT_FILENO, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* kill the thread */
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
	/* Comment the above instruction and uncomment this one to debug 
	 * using strace */
	//BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)
};

struct sock_fprog  bpf = {
	.len = (unsigned short)( sizeof bpfcode / sizeof bpfcode[0] ),
	.filter = bpfcode 
};

int main(int argc, char **argv)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		printf("prctl no_new_privs\n");
		_exit(EXIT_FAILURE);
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bpf) == -1) {
		printf("prctl seccomp_mode_filter\n");
		_exit(EXIT_FAILURE);
	}

	int fd1 = dup(STDOUT_FILENO);
	
	/* Uncomment and compare the results */
	//int fd2 = dup(STDERR_FILENO);

	return 0;
}
