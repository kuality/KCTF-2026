#define _GNU_SOURCE

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define PWN_UID 2000U
#define HANDLER_COUNT 16U
#define VM_STACK_WORDS 64U
#define TAPE_WORDS 256U
#define MAX_INSNS 192U
#define MAX_STEPS 384U
#define MAX_OUTPUTS 24U

enum opcode {
    OP_HALT = 0x00,
    OP_PUSH = 0x01,
    OP_DROP = 0x02,
    OP_DUP = 0x03,
    OP_SWAP = 0x04,
    OP_ADD = 0x05,
    OP_SUB = 0x06,
    OP_XOR = 0x07,
    OP_LOAD = 0x08,
    OP_STORE = 0x09,
    OP_PRINT = 0x0a,
    OP_INPUT = 0x0b,
    OP_HOME = 0x0c,
    OP_NOP = 0x0d,
    OP_RESERVED = 0x0e,
    OP_TRIGGER = 0x0f,
};

struct instruction {
    uint8_t opcode;
    uint8_t flags;
    int16_t offset;
    uint32_t reserved;
    uint64_t immediate;
};

struct vm;
typedef void (*handler_fn)(struct vm *, const struct instruction *);

struct vm {
    uint64_t cookie;
    uint64_t *tape_base;
    uint64_t *tape_origin;
    uint64_t output_count;
    handler_fn handlers[HANDLER_COUNT];
    uint64_t stack[VM_STACK_WORDS];
    uint64_t sp;
    uint64_t halted;
    uint64_t tape[TAPE_WORDS];
};

_Static_assert(sizeof(struct instruction) == 16, "instruction ABI changed");
_Static_assert(offsetof(struct vm, tape) % 16 == 0, "tape must be aligned");
_Static_assert(offsetof(struct vm, tape_base) % 8 == 0, "unaligned tape_base");

static void die(const char *message);

static ssize_t read_exact(int fd, void *buffer, size_t length) {
    uint8_t *cursor = buffer;
    size_t done = 0;

    while (done < length) {
        ssize_t result = read(fd, cursor + done, length - done);
        if (result == 0) {
            return (ssize_t)done;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        done += (size_t)result;
    }
    return (ssize_t)done;
}

static void write_all(int fd, const void *buffer, size_t length) {
    const uint8_t *cursor = buffer;
    size_t done = 0;

    while (done < length) {
        ssize_t result = write(fd, cursor + done, length - done);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            _exit(1);
        }
        done += (size_t)result;
    }
}

static void die(const char *message) {
    size_t length = 0;
    while (message[length] != '\0') {
        length++;
    }
    write_all(STDOUT_FILENO, message, length);
    _exit(1);
}

static void emit_u64(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char line[19];
    size_t i;

    line[0] = '0';
    line[1] = 'x';
    for (i = 0; i < 16; i++) {
        unsigned shift = (unsigned)(60 - (i * 4));
        line[2 + i] = digits[(value >> shift) & 0xfU];
    }
    line[18] = '\n';
    write_all(STDOUT_FILENO, line, sizeof(line));
}

static int vm_push(struct vm *vm, uint64_t value) {
    if (vm->sp >= VM_STACK_WORDS) {
        vm->halted = 1;
        return -1;
    }
    vm->stack[vm->sp++] = value;
    return 0;
}

static int vm_pop(struct vm *vm, uint64_t *value) {
    if (vm->sp == 0) {
        vm->halted = 1;
        return -1;
    }
    *value = vm->stack[--vm->sp];
    return 0;
}

static void op_halt(struct vm *vm, const struct instruction *instruction) {
    (void)instruction;
    vm->halted = 1;
}

static void op_push(struct vm *vm, const struct instruction *instruction) {
    (void)vm_push(vm, instruction->immediate);
}

static void op_drop(struct vm *vm, const struct instruction *instruction) {
    uint64_t unused;
    (void)instruction;
    (void)vm_pop(vm, &unused);
}

static void op_dup(struct vm *vm, const struct instruction *instruction) {
    (void)instruction;
    if (vm->sp == 0 || vm->sp >= VM_STACK_WORDS) {
        vm->halted = 1;
        return;
    }
    vm->stack[vm->sp] = vm->stack[vm->sp - 1];
    vm->sp++;
}

static void op_swap(struct vm *vm, const struct instruction *instruction) {
    uint64_t temporary;
    (void)instruction;
    if (vm->sp < 2) {
        vm->halted = 1;
        return;
    }
    temporary = vm->stack[vm->sp - 1];
    vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];
    vm->stack[vm->sp - 2] = temporary;
}

static void op_add(struct vm *vm, const struct instruction *instruction) {
    uint64_t left;
    uint64_t right;
    (void)instruction;
    if (vm_pop(vm, &right) < 0 || vm_pop(vm, &left) < 0) {
        return;
    }
    (void)vm_push(vm, left + right);
}

static void op_sub(struct vm *vm, const struct instruction *instruction) {
    uint64_t left;
    uint64_t right;
    (void)instruction;
    if (vm_pop(vm, &right) < 0 || vm_pop(vm, &left) < 0) {
        return;
    }
    (void)vm_push(vm, left - right);
}

static void op_xor(struct vm *vm, const struct instruction *instruction) {
    uint64_t left;
    uint64_t right;
    (void)instruction;
    if (vm_pop(vm, &right) < 0 || vm_pop(vm, &left) < 0) {
        return;
    }
    (void)vm_push(vm, left ^ right);
}

static void op_load(struct vm *vm, const struct instruction *instruction) {
    int16_t index = instruction->offset;
    uintptr_t address;

    /* BUG: the signed index is checked only against the upper bound. */
    if (index >= (int16_t)TAPE_WORDS) {
        vm->halted = 1;
        return;
    }
    address = (uintptr_t)vm->tape_base + ((intptr_t)index * 8);
    (void)vm_push(vm, *(volatile uint64_t *)address);
}

static void op_store(struct vm *vm, const struct instruction *instruction) {
    int16_t index = instruction->offset;
    uintptr_t address;
    uint64_t value;

    /* BUG: the signed index is checked only against the upper bound. */
    if (index >= (int16_t)TAPE_WORDS || vm_pop(vm, &value) < 0) {
        vm->halted = 1;
        return;
    }
    address = (uintptr_t)vm->tape_base + ((intptr_t)index * 8);
    *(volatile uint64_t *)address = value;
}

static void op_print(struct vm *vm, const struct instruction *instruction) {
    uint64_t value;
    (void)instruction;
    if (vm->output_count >= MAX_OUTPUTS || vm_pop(vm, &value) < 0) {
        vm->halted = 1;
        return;
    }
    vm->output_count++;
    emit_u64(value);
}

static void op_input(struct vm *vm, const struct instruction *instruction) {
    uint64_t value;
    (void)instruction;
    write_all(STDOUT_FILENO, "word> ", 6);
    if (read_exact(STDIN_FILENO, &value, sizeof(value)) != (ssize_t)sizeof(value)) {
        vm->halted = 1;
        return;
    }
    (void)vm_push(vm, value);
}

static void op_home(struct vm *vm, const struct instruction *instruction) {
    (void)instruction;
    vm->tape_base = vm->tape_origin;
}

static void op_nop(struct vm *vm, const struct instruction *instruction) {
    (void)vm;
    (void)instruction;
}

static void op_reserved(struct vm *vm, const struct instruction *instruction) {
    (void)instruction;
    vm->halted = 1;
}

static void op_trigger(struct vm *vm, const struct instruction *instruction) {
    (void)instruction;
    write_all(STDOUT_FILENO, "sealed\n", 7);
    vm->halted = 1;
}

/*
 * The normal crash-recovery path used by the VM's test fixture restores RSP
 * from the immutable tape-origin slot.  It is deliberately retained in the
 * stripped release binary so that the challenge has one stable pivot.
 */
__attribute__((naked, noinline, used, no_stack_protector,
               visibility("hidden")))
void vm_restore_frame(void) {
    __asm__ volatile("mov 0x10(%rdi), %rsp\n\t"
                     "ret\n\t");
}

/* A single-register restore primitive from the same recovery fixture. */
__attribute__((naked, noinline, used, no_stack_protector,
               visibility("hidden")))
void vm_restore_operand(void) {
    __asm__ volatile("pop %rdx\n\t"
                     "ret\n\t");
}

static void initialize_vm(struct vm *vm) {
    static const handler_fn defaults[HANDLER_COUNT] = {
        op_halt,    op_push,  op_drop,     op_dup,
        op_swap,    op_add,   op_sub,      op_xor,
        op_load,    op_store, op_print,    op_input,
        op_home,    op_nop,   op_reserved, op_trigger,
    };
    size_t index;

    vm->cookie = 0x504150455257564dULL;
    vm->tape_base = vm->tape;
    vm->tape_origin = vm->tape;
    for (index = 0; index < HANDLER_COUNT; index++) {
        vm->handlers[index] = defaults[index];
    }
}

static void execute_vm(struct vm *vm, const struct instruction *program,
                       size_t instruction_count) {
    size_t pc = 0;
    size_t steps = 0;

    while (!vm->halted && pc < instruction_count && steps < MAX_STEPS) {
        const struct instruction *instruction = &program[pc++];
        uint8_t opcode = instruction->opcode;
        handler_fn handler;

        if (opcode >= HANDLER_COUNT || instruction->flags != 0 ||
            instruction->reserved != 0) {
            vm->halted = 1;
            break;
        }
        handler = vm->handlers[opcode];
        handler(vm, instruction);
        steps++;
    }
    if (steps >= MAX_STEPS) {
        die("budget exhausted\n");
    }
}

static void drop_to_user_keep_saved_pwn(void) {
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;

    if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0) {
        die("uid query failed\n");
    }
    if (effective_uid == PWN_UID && real_uid != PWN_UID) {
        if (setresuid(real_uid, real_uid, effective_uid) < 0) {
            die("uid drop failed\n");
        }
        if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0 ||
            real_uid == PWN_UID || effective_uid == PWN_UID ||
            saved_uid != PWN_UID) {
            die("uid state invalid\n");
        }
        return;
    }
    if (real_uid != effective_uid) {
        die("setuid installation invalid\n");
    }
}

#define ALLOW_SYSCALL(name)                                                   \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_##name, 0, 1),         \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static void install_sandbox(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(openat),
        ALLOW_SYSCALL(exit),
        ALLOW_SYSCALL(exit_group),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_setuid, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PWN_UID, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)(offsetof(struct seccomp_data, args[0]) + 4)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0) {
        die("sandbox failed\n");
    }
}

int main(void) {
    struct instruction program[MAX_INSNS];
    struct vm *vm;
    uint32_t byte_count;
    size_t instruction_count;

    drop_to_user_keep_saved_pwn();
    static const char banner[] =
        "paperweight vm v1\n"
        "send: <u32 byte-count><16-byte instructions>\n";

    write_all(STDOUT_FILENO, banner, sizeof(banner) - 1);

    if (read_exact(STDIN_FILENO, &byte_count, sizeof(byte_count)) !=
        (ssize_t)sizeof(byte_count)) {
        die("short header\n");
    }
    if (byte_count == 0 || byte_count > sizeof(program) ||
        (byte_count % sizeof(struct instruction)) != 0) {
        die("bad program size\n");
    }
    if (read_exact(STDIN_FILENO, program, byte_count) != (ssize_t)byte_count) {
        die("short program\n");
    }
    instruction_count = byte_count / sizeof(struct instruction);

    vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        die("allocation failed\n");
    }
    initialize_vm(vm);
    install_sandbox();
    execute_vm(vm, program, instruction_count);
    write_all(STDOUT_FILENO, "done\n", 5);
    _exit(0);
}
