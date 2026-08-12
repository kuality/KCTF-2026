#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LISTEN_PORT 1337
#define MAX_CHILDREN 16

static volatile sig_atomic_t children;

static void reap_children(int signal_number)
{
    int saved_errno = errno;
    pid_t child;

    (void)signal_number;
    while ((child = waitpid(-1, NULL, WNOHANG)) > 0) {
        if (children > 0) {
            --children;
        }
    }
    errno = saved_errno;
}

static void set_limits(void)
{
    struct rlimit core_limit = {0, 0};
    struct rlimit file_limit = {16U * 1024U * 1024U, 16U * 1024U * 1024U};
    struct rlimit descriptor_limit = {32, 32};

    (void)setrlimit(RLIMIT_CORE, &core_limit);
    (void)setrlimit(RLIMIT_FSIZE, &file_limit);
    (void)setrlimit(RLIMIT_NOFILE, &descriptor_limit);
}

int main(void)
{
    const int enabled = 1;
    struct sigaction action;
    struct sockaddr_in address;
    sigset_t child_mask;
    int listener;

    set_limits();
    memset(&action, 0, sizeof(action));
    action.sa_handler = reap_children;
    action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&action.sa_mask);
    sigemptyset(&child_mask);
    sigaddset(&child_mask, SIGCHLD);
    if (sigaction(SIGCHLD, &action, NULL) != 0 || signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt");
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(LISTEN_PORT);
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, MAX_CHILDREN) != 0) {
        perror("listen");
        return 1;
    }

    for (;;) {
        int connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        pid_t child;
        sigset_t previous_mask;

        if (connection < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }
        if (children >= MAX_CHILDREN) {
            static const char busy[] = "server busy\n";
            ssize_t ignored = write(connection, busy, sizeof(busy) - 1);
            (void)ignored;
            close(connection);
            continue;
        }

        if (sigprocmask(SIG_BLOCK, &child_mask, &previous_mask) != 0) {
            close(connection);
            continue;
        }
        child = fork();
        if (child < 0) {
            (void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
            close(connection);
            continue;
        }
        if (child == 0) {
            char *const arguments[] = {"/home/user/secondhand", NULL};
            char *const environment[] = {"PATH=/usr/bin:/bin", "LANG=C", NULL};

            (void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
            alarm(60);
            if (dup2(connection, STDIN_FILENO) < 0 ||
                dup2(connection, STDOUT_FILENO) < 0 ||
                dup2(connection, STDERR_FILENO) < 0) {
                _exit(126);
            }
            close(connection);
            close(listener);
            execve(arguments[0], arguments, environment);
            _exit(127);
        }

        ++children;
        (void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        close(connection);
    }
}
