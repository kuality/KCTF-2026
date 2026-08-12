#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void fatal(const char *what) {
    perror(what);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    struct sockaddr_in address = {0};
    int listener;
    int enabled = 1;
    unsigned long parsed_port;
    char *end = NULL;

    if (argc != 3) {
        fprintf(stderr, "usage: %s PORT PROGRAM\n", argv[0]);
        return EXIT_FAILURE;
    }
    parsed_port = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0' || parsed_port == 0 ||
        parsed_port > UINT16_MAX) {
        fatal("port");
    }

    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fatal("signal");
    }
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        fatal("socket");
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) < 0) {
        fatal("setsockopt");
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)parsed_port);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fatal("bind");
    }
    if (listen(listener, 32) < 0) {
        fatal("listen");
    }

    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        pid_t child;
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            fatal("accept4");
        }
        child = fork();
        if (child < 0) {
            close(client);
            continue;
        }
        if (child == 0) {
            close(listener);
            if (dup2(client, STDIN_FILENO) < 0 ||
                dup2(client, STDOUT_FILENO) < 0 ||
                dup2(client, STDERR_FILENO) < 0) {
                _exit(126);
            }
            if (client > STDERR_FILENO) {
                close(client);
            }
            alarm(90);
            execl(argv[2], argv[2], (char *)NULL);
            _exit(127);
        }
        close(client);
    }
}
