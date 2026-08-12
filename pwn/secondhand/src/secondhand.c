#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ITEM_COUNT 6
#define NOTE_SIZE 32

typedef struct item Item;
typedef void (*item_callback_t)(const Item *item);
typedef void (*checkout_callback_t)(void);

struct item {
    uint64_t label;
    uint64_t price;
    unsigned char note[NOTE_SIZE];
    item_callback_t preview_callback;
    uint64_t serial;
};

typedef struct __attribute__((aligned(16))) checkout_dispatch {
    checkout_callback_t callback;
    unsigned char allocation_scratch[sizeof(Item) - sizeof(checkout_callback_t)];
} CheckoutDispatch;

enum item_state {
    SLOT_EMPTY = 0,
    SLOT_LISTED,
    SLOT_SOLD,
};

_Static_assert(sizeof(Item) == 0x40, "Item must remain in the 0x50 malloc size class");
_Static_assert(offsetof(Item, preview_callback) == 0x30,
               "the callback must stay outside the eight-byte relabel range");
_Static_assert(sizeof(CheckoutDispatch) == sizeof(Item),
               "the dispatch allocation target must hold one complete Item write");
_Static_assert(_Alignof(CheckoutDispatch) >= 16,
               "the tcache target must satisfy malloc alignment checks");

static Item *items[ITEM_COUNT];
static enum item_state states[ITEM_COUNT];
static uint64_t next_serial = 1;

static void print_summary(void);
void print_flag(void) __attribute__((noinline, used, visibility("default")));
void render_item(const Item *item) __attribute__((noinline, used, visibility("default")));

CheckoutDispatch checkout_dispatch
    __attribute__((aligned(16), used, visibility("default"))) = {
        .callback = print_summary,
        .allocation_scratch = {0},
    };

static void die(const char *message)
{
    perror(message);
    _exit(1);
}

static void configure_io(void)
{
    if (setvbuf(stdin, NULL, _IONBF, 0) != 0 ||
        setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
        setvbuf(stderr, NULL, _IONBF, 0) != 0) {
        die("setvbuf");
    }
}

static void drop_initial_privileges(void)
{
    uid_t real_uid = getuid();
    uid_t effective_uid = geteuid();
    uid_t saved_uid = (uid_t)-1;
    uid_t check_real = (uid_t)-1;
    uid_t check_effective = (uid_t)-1;

    if (getresuid(&check_real, &check_effective, &saved_uid) != 0) {
        die("getresuid");
    }

    if (check_real != real_uid || check_effective != effective_uid) {
        fputs("credential state error\n", stderr);
        _exit(1);
    }

    /*
     * In deployment the file is setuid-pwn and is executed by uid user.
     * Keep only pwn as the saved uid; normal parsing runs with both real and
     * effective uid set to user.  A same-uid launch is retained solely for
     * offline replay with the participant package.
     */
    if (effective_uid != real_uid) {
        if (setresuid(real_uid, real_uid, effective_uid) != 0) {
            die("setresuid(drop)");
        }

        if (getresuid(&check_real, &check_effective, &saved_uid) != 0 ||
            check_real != real_uid || check_effective != real_uid ||
            saved_uid != effective_uid) {
            fputs("privilege drop verification failed\n", stderr);
            _exit(1);
        }
    }
}

static int read_line(char *buffer, size_t size)
{
    size_t length;

    if (fgets(buffer, (int)size, stdin) == NULL) {
        return 0;
    }

    length = strlen(buffer);
    if (length != 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
        return 1;
    }

    if (length + 1 == size) {
        int character;
        do {
            character = getchar();
        } while (character != '\n' && character != EOF);
    }

    return 1;
}

static uint64_t read_u64(const char *prompt, int base)
{
    char buffer[64];
    char *end = NULL;
    unsigned long long value;

    for (;;) {
        fputs(prompt, stdout);
        if (!read_line(buffer, sizeof(buffer))) {
            _exit(0);
        }

        if (buffer[0] == '-' || buffer[0] == '\0') {
            puts("invalid number");
            continue;
        }

        errno = 0;
        value = strtoull(buffer, &end, base);
        if (errno == 0 && end != buffer && *end == '\0') {
            return (uint64_t)value;
        }

        puts("invalid number");
    }
}

static size_t read_index(void)
{
    uint64_t index = read_u64("index> ", 10);

    if (index >= ITEM_COUNT || states[index] == SLOT_EMPTY) {
        puts("no such item");
        return ITEM_COUNT;
    }

    return (size_t)index;
}

static size_t find_empty_slot(void)
{
    size_t index;

    for (index = 0; index < ITEM_COUNT; ++index) {
        if (states[index] == SLOT_EMPTY) {
            return index;
        }
    }

    return ITEM_COUNT;
}

void render_item(const Item *item)
{
    printf("listed label=%016" PRIx64 " price=%" PRIu64 " serial=%" PRIu64 "\n",
           item->label, item->price, item->serial);
}

static void consign_item(void)
{
    static const unsigned char default_note[NOTE_SIZE] = "inspected secondhand inventory";
    size_t index = find_empty_slot();
    Item *item;

    if (index == ITEM_COUNT) {
        puts("the counter is full");
        return;
    }

    item = malloc(sizeof(*item));
    if (item == NULL) {
        die("malloc");
    }

    memset(item, 0, sizeof(*item));
    item->label = read_u64("label (hex)> ", 16);
    item->price = read_u64("price> ", 10);
    memcpy(item->note, default_note, sizeof(default_note));
    item->preview_callback = render_item;
    item->serial = next_serial++;

    items[index] = item;
    states[index] = SLOT_LISTED;
    printf("stored in slot %zu\n", index);
}

static void preview_item(void)
{
    size_t index = read_index();
    Item *item;
    uintptr_t callback_bits = 0;

    if (index == ITEM_COUNT) {
        return;
    }

    item = items[index];
    if (states[index] == SLOT_LISTED) {
        render_item(item);
        return;
    }

    memcpy(&callback_bits, &item->preview_callback, sizeof(callback_bits));

    /* Deliberate UAF read: only sold slots expose allocator/callback words. */
    printf("storage word: %016" PRIx64 "\n", item->label);
    printf("preview callback: %016" PRIxPTR "\n", callback_bits);

    /* A corrupted per-item callback is never invoked as an alternate win path. */
    if (item->preview_callback != render_item) {
        puts("callback seal mismatch");
        return;
    }
    render_item(item);
}

static void relabel_item(void)
{
    size_t index = read_index();

    if (index == ITEM_COUNT) {
        return;
    }

    /* Deliberate UAF write, restricted to the first eight-byte tcache word. */
    items[index]->label = read_u64("new label (hex)> ", 16);
    puts("label updated");
}

static void sell_item(void)
{
    size_t index = read_index();

    if (index == ITEM_COUNT) {
        return;
    }
    if (states[index] != SLOT_LISTED) {
        puts("already sold");
        return;
    }

    free(items[index]);
    states[index] = SLOT_SOLD;
    /* Deliberate bug: items[index] is not cleared. */
    puts("sale complete");
}

static void print_summary(void)
{
    puts("settlement complete; no premium callback selected");
}

void print_flag(void)
{
    uid_t real_uid = (uid_t)-1;
    uid_t effective_uid = (uid_t)-1;
    uid_t saved_uid = (uid_t)-1;
    const char *path;
    char buffer[160];
    ssize_t length;
    int fd;
    int deployed_setuid;

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0) {
        die("getresuid(win)");
    }

    deployed_setuid = (saved_uid != real_uid);
    if (deployed_setuid) {
        if (effective_uid != real_uid || seteuid(saved_uid) != 0) {
            die("seteuid(win)");
        }
        path = "/home/pwn/flag";
    } else {
        /* Offline replay only; the container never stores a flag at this path. */
        path = "./flag";
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        die("open(flag)");
    }
    length = read(fd, buffer, sizeof(buffer));
    if (length < 0) {
        die("read(flag)");
    }
    close(fd);

    if (deployed_setuid && seteuid(real_uid) != 0) {
        die("seteuid(drop-after-win)");
    }

    if (length > 0 && write(STDOUT_FILENO, buffer, (size_t)length) != length) {
        die("write(flag)");
    }
}

static void settle(void)
{
    checkout_callback_t callback = checkout_dispatch.callback;

    if (callback == NULL) {
        puts("dispatch slot is empty");
        return;
    }
    callback();
}

static void print_menu(void)
{
    puts("\n-- SECONDHAND --");
    puts("1. consign item");
    puts("2. preview item");
    puts("3. relabel item");
    puts("4. sell item");
    puts("5. settle counter");
    puts("6. leave");
}

int main(void)
{
    drop_initial_privileges();
    configure_io();
    alarm(55);

    puts("Secondhand consignment terminal");
    for (;;) {
        uint64_t choice;

        print_menu();
        choice = read_u64("> ", 10);
        switch (choice) {
        case 1:
            consign_item();
            break;
        case 2:
            preview_item();
            break;
        case 3:
            relabel_item();
            break;
        case 4:
            sell_item();
            break;
        case 5:
            settle();
            return 0;
        case 6:
            puts("goodbye");
            return 0;
        default:
            puts("invalid menu choice");
            break;
        }
    }
}
