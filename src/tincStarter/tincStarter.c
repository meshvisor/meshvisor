#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../conf.h"
#include "../pidfile/pidfile.h"
#include "../xalloc.h"

int tincStarterMain(struct config *config) {
    pid_t pid = check_pid(config->pidStarterFilePath);
    if (pid) {
        fprintf(stderr, "TincStarter: Already running with pid %d. Killing him\n", pid);
        if (kill(pid, SIGKILL) == -1) {
            fprintf(stderr, "TincStarter: Cannot kill old TincStarter %s\n", strerror(errno));
            abort();
        }
    }
    if(!write_pid(config->pidStarterFilePath)) {
        fprintf(stderr, "TincStarter: Couldn't write pid file %s: %s\n", config->pidStarterFilePath, strerror(errno));
        abort();
    }

    sigset_t sigset;
    siginfo_t siginfo;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
        fprintf(stderr, "TincStarter: Cannot block SIGUSR1: %s.\n", strerror(errno));
        return -1;
    }
    printf("TincStarter: Waiting signal\n");
    sigwaitinfo(&sigset, &siginfo);

    if (siginfo.si_signo == SIGUSR1) {
        printf("TincStarter: Got SIGUSR1, start Tinc\n");
        struct state *state = parseStateFileIfExists(config);
        if (NULL == state) {
            fprintf(stderr, "[ERROR] TincStarter: Logic Exception - state is empty\n");
            abort();
        }

        char *configOption = NULL;
        xasprintf(&configOption, "-c%s", state->configDir);
        char *pidOption = NULL;
        xasprintf(&pidOption, "--pidfile=%s", config->pidTincFilePath);
        execl("/usr/sbin/tincd"," ","-D", configOption, pidOption, NULL);
    } else {
        printf("TincStarter: Got signal '%s'\n", strsignal(siginfo.si_signo));
    }

    return 1;
}
