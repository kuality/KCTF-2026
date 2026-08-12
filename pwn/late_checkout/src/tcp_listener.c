#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LISTEN_PORT 8080
#define LISTEN_BACKLOG 32
#define USER_UID ((uid_t)2001)
#define CHALLENGE_PATH "/home/pwn/late_checkout"

static void fail(const char *message)
{
    perror(message);
    exit(EXIT_FAILURE);
}

static int create_listener(void)
{
    const int enabled = 1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };
    int server_fd;

    server_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        fail("socket");
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) != 0) {
        fail("setsockopt");
    }
    if (bind(server_fd, (const struct sockaddr *)&address, sizeof(address)) !=
        0) {
        fail("bind");
    }
    if (listen(server_fd, LISTEN_BACKLOG) != 0) {
        fail("listen");
    }
    return server_fd;
}

static void serve_connection(int server_fd, int client_fd)
{
    if (close(server_fd) != 0) {
        _exit(EXIT_FAILURE);
    }

    for (int stream_fd = STDIN_FILENO; stream_fd <= STDERR_FILENO;
         ++stream_fd) {
        if (dup2(client_fd, stream_fd) < 0) {
            _exit(EXIT_FAILURE);
        }
    }
    if (client_fd > STDERR_FILENO) {
        (void)close(client_fd);
    }

    (void)alarm(40);
    execl(CHALLENGE_PATH, CHALLENGE_PATH, (char *)NULL);
    _exit(127);
}

int main(void)
{
    struct sigaction child_action = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_NOCLDWAIT | SA_RESTART,
    };
    int server_fd;

    if (getuid() != USER_UID || geteuid() != USER_UID) {
        fputs("listener must run as uid 2001\n", stderr);
        return EXIT_FAILURE;
    }

    if (sigemptyset(&child_action.sa_mask) != 0 ||
        sigaction(SIGCHLD, &child_action, NULL) != 0 ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fail("signal setup");
    }

    server_fd = create_listener();
    for (;;) {
        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        pid_t child_pid;

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)sleep(1);
            continue;
        }

        child_pid = fork();
        if (child_pid == 0) {
            serve_connection(server_fd, client_fd);
        }
        (void)close(client_fd);
    }
}
