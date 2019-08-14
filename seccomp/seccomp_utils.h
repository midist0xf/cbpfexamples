#define arch_num (offsetof(struct seccomp_data, arch))
#define syscall_num (offsetof(struct seccomp_data, nr))

#define VERIFY_ARCHITECTURE(arch_audit_num) \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_num), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, arch_audit_num, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define LOAD_SYSCALL_NUMBER \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_num)

#define ALLOW_SYSCALL(syscall_name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##syscall_name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_THREAD \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define TRAP_THREAD \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)
