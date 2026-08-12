#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define USER_UID 2001
#define PWN_UID 2000
#define APPROVAL_MAGIC UINT32_C(0x0539)
#define REPORT_CAPACITY 256
#define MAX_CONVERSIONS 12
#define MAX_FIELD_WIDTH 4096U
#define FLAG_PATH "/home/pwn/flag"

volatile uint32_t approval __attribute__((section(".approval"), aligned(8))) = 0;

static uid_t worker_uid;
static uid_t privileged_uid;
static int privilege_ready;

static void fatal(const char *message)
{
    dprintf(STDERR_FILENO, "inkspill: %s\n", message);
    _exit(1);
}

static void initialize_privileges(void)
{
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0)
        fatal("getresuid failed");
    if (real_uid != USER_UID)
        fatal("unexpected service uid");

    worker_uid = real_uid;
    privileged_uid = effective_uid;
    privilege_ready = (effective_uid == PWN_UID && saved_uid == PWN_UID);

    /* A setuid-pwn execution starts as (user, pwn, pwn).  Drop the
     * effective ID before parsing any attacker-controlled bytes, while
     * deliberately retaining pwn only as the saved ID. */
    if (setresuid(worker_uid, worker_uid, privileged_uid) != 0)
        fatal("cannot enter worker mode");
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0)
        fatal("getresuid verification failed");
    if (real_uid != worker_uid || effective_uid != worker_uid ||
        saved_uid != privileged_uid)
        fatal("worker privilege invariant failed");
}

static ssize_t read_binary_line(unsigned char *buffer, size_t capacity)
{
    size_t used = 0;
    unsigned char byte = 0;

    if (capacity == 0)
        return -1;

    while (used + 1 < capacity) {
        ssize_t amount = read(STDIN_FILENO, &byte, 1);

        if (amount == 0)
            break;
        if (amount < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (byte == '\n')
            break;
        buffer[used++] = byte;
    }

    buffer[used] = '\0';

    if (used + 1 == capacity && byte != '\n') {
        do {
            ssize_t amount = read(STDIN_FILENO, &byte, 1);
            if (amount == 0)
                break;
            if (amount < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
        } while (byte != '\n');
    }

    return (ssize_t)used;
}

static int parse_decimal(const unsigned char *text, size_t *cursor,
                         unsigned int *value)
{
    size_t index = *cursor;
    unsigned int parsed = 0;
    int saw_digit = 0;

    while (text[index] >= '0' && text[index] <= '9') {
        unsigned int digit = (unsigned int)(text[index] - '0');

        saw_digit = 1;
        if (parsed > MAX_FIELD_WIDTH ||
            parsed > (MAX_FIELD_WIDTH - digit) / 10U)
            return -1;
        parsed = parsed * 10U + digit;
        ++index;
    }

    *cursor = index;
    *value = parsed;
    return saw_digit;
}

static int report_format_allowed(const unsigned char *format)
{
    size_t cursor = 0;
    unsigned int conversions = 0;
    unsigned int half_writes = 0;

    while (format[cursor] != '\0') {
        unsigned int number = 0;
        int length_h = 0;
        size_t number_start;
        int number_result;
        unsigned char conversion;

        if (format[cursor++] != '%')
            continue;
        if (format[cursor] == '%') {
            ++cursor;
            continue;
        }
        if (++conversions > MAX_CONVERSIONS)
            return 0;

        number_start = cursor;
        number_result = parse_decimal(format, &cursor, &number);
        if (number_result < 0)
            return 0;
        if (number_result > 0 && format[cursor] == '$') {
            if (number == 0 || number > 32U)
                return 0;
            ++cursor;
        } else {
            cursor = number_start;
        }

        while (format[cursor] == '-' || format[cursor] == '+' ||
               format[cursor] == ' ' || format[cursor] == '#' ||
               format[cursor] == '0')
            ++cursor;

        if (format[cursor] == '*')
            return 0;
        number_result = parse_decimal(format, &cursor, &number);
        if (number_result < 0 || (number_result > 0 && number > MAX_FIELD_WIDTH))
            return 0;

        if (format[cursor] == '.') {
            ++cursor;
            if (format[cursor] == '*')
                return 0;
            number_result = parse_decimal(format, &cursor, &number);
            if (number_result < 0 || (number_result > 0 && number > MAX_FIELD_WIDTH))
                return 0;
        }

        if (format[cursor] == 'h') {
            length_h = 1;
            ++cursor;
            if (format[cursor] == 'h')
                return 0;
        } else if (format[cursor] == 'l' || format[cursor] == 'j' ||
                   format[cursor] == 'z' || format[cursor] == 't' ||
                   format[cursor] == 'L') {
            return 0;
        }

        conversion = format[cursor];
        if (conversion == '\0')
            return 0;
        ++cursor;

        if (conversion == 'n') {
            if (!length_h || ++half_writes > 1)
                return 0;
            continue;
        }
        if (length_h)
            return 0;
        if (conversion != 'c' && conversion != 'p' && conversion != 'x' &&
            conversion != 'X' && conversion != 'u' && conversion != 'd' &&
            conversion != 'i' && conversion != 'o')
            return 0;
    }

    return 1;
}

static void submit_report(void)
{
    unsigned char report[REPORT_CAPACITY] __attribute__((aligned(16)));
    ssize_t length;

    memset(report, 0, sizeof(report));
    fputs("report> ", stdout);
    length = read_binary_line(report, sizeof(report));
    if (length < 0)
        fatal("report read failed");
    if (length == 0) {
        puts("[-] Empty reports are discarded.");
        return;
    }
    if (!report_format_allowed(report)) {
        puts("[-] The printing press rejected that layout.");
        return;
    }

    fputs("[press] ", stdout);
    /* Intentionally vulnerable: the report itself is the format string. */
    printf((char *)report);
    putchar('\n');
    puts("[+] Report queued for editorial review.");
}

static void print_editor_archive(void)
{
    char flag[96];
    ssize_t amount;
    int descriptor;
    struct stat metadata;

    if (approval != APPROVAL_MAGIC) {
        puts("[-] Archive request is not approved.");
        return;
    }
    approval = 0;
    puts("[+] Approval accepted.");

    if (!privilege_ready) {
        puts("[-] Privileged archive is unavailable outside the service image.");
        return;
    }

    /* This is the only path that restores the saved pwn effective UID. */
    if (setresuid((uid_t)-1, privileged_uid, (uid_t)-1) != 0)
        fatal("cannot enter archive mode");
    if (geteuid() != privileged_uid)
        fatal("archive privilege invariant failed");

    descriptor = open(FLAG_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        fatal("cannot open archive");
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 || metadata.st_size >= (off_t)sizeof(flag)) {
        close(descriptor);
        fatal("invalid archive metadata");
    }
    amount = read(descriptor, flag, sizeof(flag) - 1);
    close(descriptor);
    if (amount <= 0)
        fatal("cannot read archive");
    flag[amount] = '\0';

    if (setresuid((uid_t)-1, worker_uid, (uid_t)-1) != 0)
        fatal("cannot leave archive mode");
    if (geteuid() != worker_uid)
        fatal("worker privilege restore failed");

    fputs("[archive] ", stdout);
    fputs(flag, stdout);
    if (flag[amount - 1] != '\n')
        putchar('\n');
}

static int read_menu_choice(void)
{
    unsigned char line[16];
    ssize_t length;

    fputs("\n1. Submit report\n2. Print editor archive\n3. Quit\n> ", stdout);
    length = read_binary_line(line, sizeof(line));
    if (length <= 0)
        return 3;
    if (length == 1 && line[0] >= '1' && line[0] <= '3')
        return line[0] - '0';
    return 0;
}

int main(void)
{
    int report_submitted = 0;

    initialize_privileges();
    alarm(30);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("=================================");
    puts(" Inkspill Newsroom Tip Service");
    puts("=================================");

    for (;;) {
        switch (read_menu_choice()) {
        case 1:
            if (report_submitted) {
                puts("[-] One report per connection.");
            } else {
                report_submitted = 1;
                submit_report();
            }
            break;
        case 2:
            print_editor_archive();
            break;
        case 3:
            puts("Goodbye.");
            return 0;
        default:
            puts("[-] Invalid menu selection.");
            break;
        }
    }
}
