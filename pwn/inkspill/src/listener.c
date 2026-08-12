#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LISTEN_PORT 1337
#define USER_UID 2001
#define MAX_CHILDREN 32
#define CHALLENGE_PATH "/home/user/inkspill"

static volatile sig_atomic_t active_children;

static void reap_children(int signal_number)
{
    int saved_errno = errno;
    int status;
    pid_t child;

    (void)signal_number;
    while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
        (void)child;
        if (active_children > 0)
            --active_children;
    }
    errno = saved_errno;
}

static void die(const char *operation)
{
    perror(operation);
    exit(EXIT_FAILURE);
}

static void serve_client(int listener, int client)
{
    char *const arguments[] = {(char *)CHALLENGE_PATH, NULL};
    char *const environment[] = {
        (char *)"LANG=C",
        (char *)"LC_ALL=C",
        (char *)"PATH=/usr/bin:/bin",
        NULL,
    };

    if (dup2(client, STDIN_FILENO) < 0 ||
        dup2(client, STDOUT_FILENO) < 0 ||
        dup2(client, STDERR_FILENO) < 0)
        _exit(111);
    close(client);
    close(listener);
    execve(CHALLENGE_PATH, arguments, environment);
    _exit(111);
}

int main(void)
{
    struct sockaddr_in address;
    struct sigaction action;
    sigset_t child_mask;
    sigset_t previous_mask;
    int listener;
    int enabled = 1;

    if (getuid() != USER_UID || geteuid() != USER_UID) {
        fputs("listener must run as user\n", stderr);
        return EXIT_FAILURE;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = reap_children;
    action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0)
        die("sigaction");
    signal(SIGPIPE, SIG_IGN);

    sigemptyset(&child_mask);
    sigaddset(&child_mask, SIGCHLD);

    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        die("socket");
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) != 0)
        die("setsockopt");

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(LISTEN_PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0)
        die("bind");
    if (listen(listener, MAX_CHILDREN) != 0)
        die("listen");

    for (;;) {
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        pid_t child;

        if (client < 0) {
            if (errno == EINTR)
                continue;
            die("accept4");
        }
        if (active_children >= MAX_CHILDREN) {
            close(client);
            continue;
        }

        if (sigprocmask(SIG_BLOCK, &child_mask, &previous_mask) != 0) {
            close(client);
            continue;
        }
        child = fork();
        if (child == 0) {
            sigprocmask(SIG_SETMASK, &previous_mask, NULL);
            serve_client(listener, client);
        }
        if (child > 0)
            ++active_children;
        close(client);
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
    }
}
