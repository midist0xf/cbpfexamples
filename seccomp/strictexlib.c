#include <seccomp.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

/* initialize arguments rules array for openat rule */
struct scmp_arg_cmp arg_cmp[] = { SCMP_A2(SCMP_CMP_EQ, O_WRONLY|O_CREAT),
	SCMP_A3(SCMP_CMP_EQ, S_IWUSR|S_IRUSR),
        SCMP_A0(SCMP_CMP_EQ, AT_FDCWD)
};

/* The filter allows the same system calls as seccomp strict mode plus
 * close, dup(STDOUT_FILENO),
 * open("hello.txt", O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR)
 * and system calls needed to use seccomp_export_pfc.
 * This program also shows an example of seccomp_system_priority and 
 * seccomp_eport_pfc usage. */ 
int main(int argc, char **argv){

	int r;

	/* initialize filter state and set
	 * kill as deafult action */
	scmp_filter_ctx ctx;

	/* susbstitute SCMP_ACT_KILL with SCMP_ACT_TRAP to
	 * debug using strace */
	ctx = seccomp_init(SCMP_ACT_KILL);

	if (ctx == NULL){
		_exit(EXIT_FAILURE);
	}

	/* add rules to build the whitelist */
	/* exit_group */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	if (r<0) seccomp_release(ctx);
	/* exit */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	if (r<0) seccomp_release(ctx);
	/* write */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (r<0) seccomp_release(ctx);
	/* read */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if (r<0) seccomp_release(ctx);
	/* sigreturn */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	/* dup(STDOUT_FILENO) */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 1,
			SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
	if (r<0) seccomp_release(ctx);
	/* open("hello.txt", O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR) ->
	 * openat(AT_FDCWD, "hello.txt", O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR) */
	r = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 2,
			arg_cmp);
	if (r<0) seccomp_release(ctx);
	/* close */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (r<0) seccomp_release(ctx);

	/* rules needed to use seccomp_export_pfc */
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	if (r<0) seccomp_release(ctx);
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
	if (r<0) seccomp_release(ctx);
	r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	if (r<0) seccomp_release(ctx);

	/* Increase the priority of system call fstat. Uncomment
	 * the line below and the call to seccomp_export_pfc to 
	 * see how the priority affect the position of the system
	 * call in the filter. */
	//r = seccomp_syscall_priority(ctx, SCMP_SYS(fstat), 1); 
	//if (r<0) seccomp_release(ctx);

	/* load the filter into the kernel */
	r = seccomp_load(ctx);
	if (r<0) seccomp_release(ctx);

        /* write to stdout human readable format of the filter */	
	//r = seccomp_export_pfc(ctx, STDOUT_FILENO);
	//if (r<0) seccomp_release(ctx);

	/* release the filter state */
	seccomp_release(ctx);

	/* test the filter with some calls */
	int fd1 = dup(STDOUT_FILENO);

	int fd = open("hello.txt", O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR );

	/* Comment the line above, uncomment the line below and 
	 * compare the results */
	//int fd = open("hello2.txt", O_RDONLY|O_CREAT, S_IRUSR );
	
	close(fd);

	_exit(EXIT_SUCCESS);
}
