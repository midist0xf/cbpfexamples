#define _GNU_SOURCE
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
   /* activate seccomp strict mode */ 
   if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == -1){
      printf("prctl seccomp_mode_strict\n");
      syscall(__NR_exit, EXIT_FAILURE);
   }

   /* syscall(2) invokation allows to call kernel's 
    * _exit syscall*/
   syscall(__NR_exit, EXIT_SUCCESS);

   /* With _exit the process gets killed because since
    * glibc 2.3 _exit is a wrapper for exit_group(2)
    * and SECCOMP_MODE_STRICT allows just read(2), write(2),
    * _exit(2) (but not exit_group(2)), and sigreturn(2).
    * Uncomment the line below and compare the results. */

   //_exit(0);
}

