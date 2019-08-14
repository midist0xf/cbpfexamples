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

/* This filter allows the same system calls as the strict mode 
 * plus dup(STODUT_FILENO) call */
struct sock_filter  bpfcode[] = {

	/* validate the architecture */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	/* load syscall number in the accumulator */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof (struct seccomp_data, nr))),
	/* check if the syscall number is allowed */
	/* _exit */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* exit_group */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_exit_group, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* write */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* read */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* sigreturn */
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_rt_sigreturn, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* dup(STDOUT_FILENO) */
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_dup, 0, 3), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,(offsetof (struct seccomp_data, args[0]))),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, STDOUT_FILENO, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	/* kill the process */
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

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &bpf)) {
		printf("seccomp");
		exit(EXIT_FAILURE);
	}

	int fd1 = dup(STDOUT_FILENO);

	/* Uncomment and compare the results */
	//int fd2 = dup(STDERR_FILENO);

	_exit(EXIT_SUCCESS);
}
