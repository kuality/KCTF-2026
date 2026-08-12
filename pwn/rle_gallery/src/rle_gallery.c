#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define TITLE_MAX 48
#define RLE_MAX 512
#define CANVAS_SIZE 96

static uid_t gallery_owner_uid = (uid_t)-1;

static void fatal(const char *message)
{
    dprintf(STDOUT_FILENO, "error: %s\n", message);
    _exit(1);
}

/*
 * The gallery worker is installed setuid-pwn, but a visitor session must run
 * with the unprivileged user's real and effective UID.  Only the saved pwn UID
 * is retained.  The maintenance helper below is not used by normal requests;
 * reaching it requires control-flow hijacking after preserving the canary.
 */
static void drop_to_visitor(void)
{
    uid_t visitor_uid = getuid();
    uid_t owner_uid = geteuid();

    gallery_owner_uid = owner_uid;
    if (setresuid(visitor_uid, visitor_uid, owner_uid) != 0) {
        fatal("cannot enter visitor mode");
    }
    if (getuid() != visitor_uid || geteuid() != visitor_uid) {
        fatal("visitor mode verification failed");
    }
}

__attribute__((force_align_arg_pointer, noinline, used))
static void restore_gallery_owner(void)
{
    uid_t owner_uid = gallery_owner_uid;

    if (owner_uid == (uid_t)-1 ||
        setresuid(owner_uid, owner_uid, owner_uid) != 0) {
        _exit(126);
    }
}

static uintptr_t stack_guard(void)
{
    uintptr_t guard;

    __asm__ volatile("mov %%fs:0x28, %0" : "=r"(guard));
    return guard;
}

static ssize_t read_line(char *buffer, size_t capacity)
{
    size_t length = 0;
    int too_long = 0;

    for (;;) {
        unsigned char byte;
        ssize_t received = read(STDIN_FILENO, &byte, 1);

        if (received == 0) {
            return -1;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (byte == '\n') {
            break;
        }
        if (byte == '\r') {
            continue;
        }
        if (length + 1 < capacity) {
            buffer[length++] = (char)byte;
        } else {
            too_long = 1;
        }
    }

    if (too_long || length == 0) {
        return -1;
    }
    buffer[length] = '\0';
    return (ssize_t)length;
}

static size_t read_rle_length(void)
{
    char line[32];
    char *end = NULL;
    unsigned long parsed;

    if (read_line(line, sizeof(line)) < 0) {
        fatal("invalid RLE length");
    }

    errno = 0;
    parsed = strtoul(line, &end, 10);
    if (errno != 0 || end == line || *end != '\0' || parsed < 2 ||
        parsed > RLE_MAX || (parsed & 1U) != 0) {
        fatal("RLE length must be an even number from 2 through 512");
    }
    return (size_t)parsed;
}

static void read_exact(unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t received = read(STDIN_FILENO, buffer + offset, length - offset);

        if (received == 0) {
            fatal("unexpected EOF in RLE stream");
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            fatal("failed to read RLE stream");
        }
        offset += (size_t)received;
    }
}

/* Permit literals, %% and positional pointer reads such as %12$p. */
static int read_only_format(const char *title)
{
    size_t cursor = 0;

    while (title[cursor] != '\0') {
        unsigned int position = 0;
        unsigned int digits = 0;

        if ((unsigned char)title[cursor] < 0x20 ||
            (unsigned char)title[cursor] > 0x7e) {
            return 0;
        }
        if (title[cursor++] != '%') {
            continue;
        }
        if (title[cursor] == '%') {
            ++cursor;
            continue;
        }
        while (isdigit((unsigned char)title[cursor]) && digits < 2) {
            position = position * 10U + (unsigned int)(title[cursor] - '0');
            ++cursor;
            ++digits;
        }
        if (digits == 0 || position == 0 || position > 40 ||
            title[cursor++] != '$' || title[cursor++] != 'p') {
            return 0;
        }
    }
    return 1;
}

__attribute__((noinline))
static void preview_title(const char *title)
{
    uintptr_t guard = stack_guard();

    fputs("Preview: ", stdout);
    printf(title,
           (void *)0x1111111111111111ULL,
           (void *)0x2222222222222222ULL,
           (void *)0x3333333333333333ULL,
           (void *)0x4444444444444444ULL,
           (void *)0x5555555555555555ULL,
           (void *)0x6666666666666666ULL,
           (void *)0x7777777777777777ULL,
           (void *)0x8888888888888888ULL,
           (void *)0x9999999999999999ULL,
           (void *)0xaaaaaaaaaaaaaaaaULL,
           (void *)guard,
           (void *)&preview_title,
           (void *)printf);
    putchar('\n');
}

__attribute__((noinline))
static void decode_picture(const unsigned char *encoded, size_t encoded_length)
{
    volatile unsigned char canvas[CANVAS_SIZE];
    size_t output_length = 0;
    size_t cursor;
    size_t repeat;

    for (repeat = 0; repeat < sizeof(canvas); ++repeat) {
        canvas[repeat] = ' ';
    }

    for (cursor = 0; cursor < encoded_length; cursor += 2) {
        unsigned int count = encoded[cursor];
        unsigned char value = encoded[cursor + 1];

        if (count == 0) {
            fatal("zero-length RLE runs are not allowed");
        }

        /* BUG: compressed length is bounded, decoded length is not. */
        for (repeat = 0; repeat < count; ++repeat) {
            canvas[output_length++] = value;
        }
    }

    fputs("Canvas: ", stdout);
    if (write(STDOUT_FILENO, (const void *)canvas, sizeof(canvas)) !=
        sizeof(canvas)) {
        fatal("failed to render canvas");
    }
    fputs("\nStored.\n", stdout);
}

int main(void)
{
    char title[TITLE_MAX + 1];
    unsigned char encoded[RLE_MAX];
    size_t encoded_length;

    drop_to_visitor();

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(60);

    puts("=== RLE Gallery ===");
    puts("Titles may contain positional pointer placeholders.");
    fputs("Title> ", stdout);
    if (read_line(title, sizeof(title)) < 0 || !read_only_format(title)) {
        fatal("title must use only literals, %%, and %N$p pointer reads");
    }
    preview_title(title);

    fputs("RLE byte length> ", stdout);
    encoded_length = read_rle_length();
    fputs("RLE bytes> ", stdout);
    read_exact(encoded, encoded_length);
    decode_picture(encoded, encoded_length);

    return 0;
}
