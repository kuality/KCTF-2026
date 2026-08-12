#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define USER_UID ((uid_t)2001)
#define PWN_UID ((uid_t)2000)
#define FLAG_PATH "/home/pwn/flag"

static void die(const char *message)
{
    (void)fputs(message, stderr);
    _exit(EXIT_FAILURE);
}

/*
 * A setuid-pwn exec starts as (ruid=user, euid=pwn, suid=pwn).  Drop both
 * active IDs before doing any challenge work, keeping only the saved pwn UID.
 */
static void enter_unprivileged_session(void)
{
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0) {
        die("credential query failed\n");
    }

    if (real_uid != USER_UID || effective_uid != PWN_UID ||
        saved_uid != PWN_UID) {
        die("setuid installation is invalid\n");
    }

    if (setresuid(USER_UID, USER_UID, PWN_UID) != 0) {
        die("credential drop failed\n");
    }

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        real_uid != USER_UID || effective_uid != USER_UID ||
        saved_uid != PWN_UID) {
        die("credential drop verification failed\n");
    }
}

/*
 * The function is intentionally unreachable from normal control flow.
 *
 * With a valid SysV AMD64 call frame, the prologue leaves RSP 16-byte aligned.
 * Returning here directly from take_last_request() leaves it misaligned, so
 * MOVAPS faults.  A one-byte ret gadget before this target restores alignment.
 * The privilege restoration exists only in this function.
 */
__attribute__((noinline, used, noreturn))
void print_receipt_secret(void)
{
    FILE *flag_file;
    char flag[96] = {0};

    __asm__ volatile("movaps (%%rsp), %%xmm0" ::: "xmm0", "memory");

    if (seteuid(PWN_UID) != 0 || getuid() != USER_UID ||
        geteuid() != PWN_UID) {
        die("privilege restoration failed\n");
    }

    flag_file = fopen(FLAG_PATH, "r");
    if (flag_file == NULL) {
        die("receipt secret is unavailable\n");
    }

    if (fgets(flag, sizeof(flag), flag_file) == NULL) {
        (void)fclose(flag_file);
        die("receipt secret is empty\n");
    }

    (void)fclose(flag_file);
    (void)fputs("Final receipt: ", stdout);
    (void)fputs(flag, stdout);
    (void)fflush(stdout);
    _exit(EXIT_SUCCESS);
}

__attribute__((noinline))
static void take_last_request(void)
{
    char last_request[64];

    (void)puts("Before you leave, write one last request for the hotel:");

    /* The sole intended vulnerability: 256 bytes into a 64-byte stack slot. */
    if (read(STDIN_FILENO, last_request, 256) < 0) {
        die("request read failed\n");
    }

    (void)puts("Your checkout is complete. Safe travels!");
}

int main(void)
{
    enter_unprivileged_session();

    (void)setvbuf(stdin, NULL, _IONBF, 0);
    (void)setvbuf(stdout, NULL, _IONBF, 0);
    (void)setvbuf(stderr, NULL, _IONBF, 0);
    (void)alarm(30);

    (void)puts("=== Late Checkout ===");
    take_last_request();
    return EXIT_SUCCESS;
}
