#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *what)
{
    perror(what);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    struct sockaddr_in address;
    int server_fd;
    int enabled = 1;
    long port;
    char *end = NULL;

    if (argc != 3) {
        fprintf(stderr, "usage: %s PORT PROGRAM\n", argv[0]);
        return EXIT_FAILURE;
    }

    errno = 0;
    port = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' ||
        port < 1 || port > 65535) {
        fputs("invalid port\n", stderr);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fail("socket");
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   &enabled, sizeof(enabled)) != 0) {
        fail("setsockopt");
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fail("bind");
    }
    if (listen(server_fd, 32) != 0) {
        fail("listen");
    }

    for (;;) {
        int client_fd = accept(server_fd, NULL, NULL);
        pid_t child;

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail("accept");
        }

        child = fork();
        if (child < 0) {
            close(client_fd);
            continue;
        }
        if (child == 0) {
            char *const child_argv[] = {argv[2], NULL};
            char *const child_env[] = {
                "PATH=/usr/bin:/bin",
                "LANG=C",
                NULL
            };

            close(server_fd);
            alarm(70);
            if (dup2(client_fd, STDIN_FILENO) < 0 ||
                dup2(client_fd, STDOUT_FILENO) < 0 ||
                dup2(client_fd, STDERR_FILENO) < 0) {
                _exit(125);
            }
            if (client_fd > STDERR_FILENO) {
                close(client_fd);
            }
            execve(argv[2], child_argv, child_env);
            _exit(127);
        }
        close(client_fd);
    }
}
