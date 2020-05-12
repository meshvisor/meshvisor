#define UNUSED(x) (void)(x)
#define DOMAIN "api.meshvisor.com"
#define API_METHOD_JOB "job"
#define API_METHOD_CONFIG "config"

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <curl/curl.h>
#include <unistd.h>
#include <ftw.h>
#include "src/cJSON/cJSON.h"
#include <time.h>
#include <errno.h>
#include <wait.h>
#include "xalloc.h"
#include "logger.h"
#include "conf.h"
#include "aes/crypt.h"
#include "request/request.h"
#include "keygen/keygen.h"
#include "tincStarter/tincStarter.h"
#include "pidfile/pidfile.h"

struct state *initNetwork(cJSON *jobData, struct config *config);
struct state *updateNetwork(cJSON *jobData, struct config *config);

bool sendHostKey(struct config *config, char *encodedHost);

void daemonMain(pid_t tincStarterPid, struct config *config, struct state *state);

static void sigchldHandler() {
    fprintf(stderr, "Daemon: TincStarter down\n");
    abort();
}

int main() {
    srand(time(NULL));
    struct config *config = parseUserConfig();
    struct state *state = parseStateFileIfExists(config);

    pid_t forkPid = fork();
    if (forkPid == -1) {
        printf("Error: Fork\n");
        abort();
    } else if (!forkPid) {
        return tincStarterMain(config);
    } else {
        pid_t pid = check_pid(config->pidMeshvisorFilePath);
        if (pid) {
            fprintf(stderr, "Daemon: Meshvisor already running with pid %d\n", pid);
            if (kill(forkPid, SIGKILL) == -1) {
                fprintf(stderr, "Daemon: Cannot send SIGKILL signal to TincStarter: %s\n", strerror(errno));
            }
            abort();
        }
        if (!write_pid(config->pidMeshvisorFilePath)) {
            fprintf(stderr, "Daemon: Couldn't write pid file %s: %s\n", config->pidMeshvisorFilePath, strerror(errno));
            abort();
        }
        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = sigchldHandler;
        sigaction(SIGCHLD, &sa, NULL);
        daemonMain(forkPid, config, state);
    }
}

bool use_logfile = false;
char *identname = NULL;
char *logfilename = NULL;

bool startTinc(pid_t tincStarterPid) {
    fprintf(stdout, "Daemon: Sending SIGUSR1 to TincStarter for start tinc .\n");
    if (kill(tincStarterPid, SIGUSR1) == -1) {
        fprintf(stderr, "Daemon: Cannot send SIGUSR1 signal: %s.\n", strerror(errno));
        return false;
    }
    return true;
}

void daemonMain(pid_t tincStarterPid, struct config *config, struct state *state) {
    //@TODO set paths if configured
    bool isTincStarted = false;
    identname = xstrdup("meshvisor");
    xasprintf(&logfilename, "%s/log/%s.log", LOCALSTATEDIR, identname);
    openlogger(identname, use_logfile ? LOGMODE_FILE : LOGMODE_STDERR);
    logger(LOG_DEBUG, "Start Debug");

    char *getJobUrl;
    xasprintf(&getJobUrl, "https://%s/%s", DOMAIN, API_METHOD_JOB);
    struct request *getJobRequest = requestInit(config, getJobUrl);

    while (1) {
        char *getJobQuery; //@TODO free
        xasprintf(&getJobQuery, "state_number=%d", state == NULL ? 0 : state->number);
        requestSetQuery(getJobRequest, getJobQuery);
        cJSON *getJobResponse = sendRequest(getJobRequest);
        if (NULL != getJobResponse) {
            char *job = cJSON_GetObjectItem(getJobResponse, "job")->valuestring;
            cJSON *jobData = cJSON_GetObjectItem(getJobResponse, "data");
            if (!strcmp(job, "nothingToDo")) {
                if (!isTincStarted) {
                    isTincStarted = startTinc(tincStarterPid);
                }
            } else if (!strcmp(job, "init")) {
                state = initNetwork(jobData, config);
                char *encodedHost = encodeFileByPath(state->hostsFilePath, config->encryptionKey, 1600);
                if (sendHostKey(config, encodedHost)) {
                    dumpState(config, state);
                    logger(LOG_DEBUG, "Daemon: Send SIGUSR1 to Tink Starter");
                    isTincStarted = startTinc(tincStarterPid);
                } else {
                    state = NULL;
                }
                free(encodedHost);
            } else if (!strcmp(job, "update")) {
//                state = updateNetwork(jobData, config);
//                dumpState(config, state);
                if (isTincStarted) {
                    fprintf(stderr, "Daemon: Sending SIGHUP to Tinc for reread configs\n");
                    if (kill(tincStarterPid, SIGHUP) == -1) {
                        fprintf(stderr, "Daemon: Cannot send SIGHUP signal to Tinc\n");
                        abort();
                    }
                } else {
                    isTincStarted = startTinc(tincStarterPid);
                }
            } else {
                logger(LOG_ERR, "Unknown job %s", job);
            }
        }
        logger(LOG_DEBUG, "Sleep %d", config->poolingRate);
        sleep(config->poolingRate);
    }
}

bool sendHostKey(struct config *config, char *encodedHost) {
    char *sendKeyUrl;
    xasprintf(&sendKeyUrl, "https://%s/%s", DOMAIN, API_METHOD_CONFIG);
    struct request *sendKeyRequest = requestInit(config, sendKeyUrl);
    requestSetPostParams(sendKeyRequest, "config", PARAM_STRING, encodedHost);
    cJSON *sendKeyResponse = sendRequest(sendKeyRequest);
    curl_easy_cleanup(sendKeyRequest->curl);
    free(sendKeyRequest);

    return NULL != sendKeyResponse;
}

int unlinkCb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    UNUSED(sb);
    UNUSED(typeflag);
    UNUSED(ftwbuf);
    int rv = remove(fpath);
    if (rv) {
        perror(fpath);
    }

    return rv;
}

struct state *initNetwork(cJSON *jobData, struct config *config) {
    cJSON *iterator = NULL;
    FILE *f = NULL;

    logger(LOG_INFO, "Start network init job");
    cJSON *network = cJSON_GetObjectItem(jobData, "network");
    struct state *state = createState(
            config,
            cJSON_GetObjectItem(jobData, "stateNumber")->valueint,
            cJSON_GetObjectItem(network, "name")->valuestring,
            cJSON_GetObjectItem(jobData, "name")->valuestring
    );

    char *networkInternalIp = cJSON_GetObjectItem(network, "internalIp")->valuestring;
    char *networkInternalMask = cJSON_GetObjectItem(network, "internalMask")->valuestring;
    char *networkNodeSubnet = cJSON_GetObjectItem(network, "nodeSubnet")->valuestring;
    char *networkExternalIp = cJSON_GetObjectItem(network, "externalIp")->valuestring;
    char *addressFamily = cJSON_GetObjectItem(jobData, "addressFamily")->valuestring;
    cJSON *connectTo = cJSON_GetObjectItem(jobData, "connectTo");
    logger(LOG_INFO, "Network name: '%s'; Node name: '%s';", state->network, state->node);
    logger(LOG_DEBUG, "Remove config folder '%s' if exists", state->configDir);
    nftw(state->configDir, unlinkCb, 64, FTW_DEPTH | FTW_PHYS);
    logger(LOG_DEBUG, "Create config folders");
    mkdir(config->networkDir, 0755);
    mkdir(state->configDir, 0755);
    mkdir(state->hostsDir, 0755);

    f = fopen(state->tincConfPath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc config file: '%s'", state->tincConfPath);
        abort();
    }
    fprintf(f, "Name = %s\n", state->node);
    fprintf(f, "AddressFamily = %s\n", addressFamily);
    fprintf(f, "Interface = %s\n", config->interface);
    cJSON_ArrayForEach(iterator, connectTo) {
        fprintf(f, "ConnectTo = %s\n", iterator->valuestring);
    }
    fclose(f);

    f = fopen(state->hostsFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create host file: '%s'", state->hostsFilePath);
        abort();
    }
    if (NULL != networkExternalIp) {
        fprintf(f, "Address = %s\n", networkExternalIp);
    }
    fprintf(f, "Subnet = %s\n", networkNodeSubnet);
    fclose(f);
    logger(LOG_DEBUG, "Generate keys");
    keygen(state->configDir, state->hostsFilePath);

    f = fopen(state->tincUpFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc-up file: '%s'", state->tincUpFilePath);
        abort();
    }
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "ifconfig $INTERFACE %s netmask %s\n", networkInternalIp, networkInternalMask);
    fclose(f);

    f = fopen(state->tincDownFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc-down file: '%s'", state->tincDownFilePath);
        abort();
    }
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "ifconfig $INTERFACE down\n");
    fclose(f);

    iterator = NULL;
    cJSON *hosts = cJSON_GetObjectItem(jobData, "hosts");
    cJSON_ArrayForEach(iterator, hosts) {
        char *hostName = cJSON_GetObjectItem(iterator, "name")->valuestring;
        char *hostEncodedConfig = cJSON_GetObjectItem(iterator, "config")->valuestring;
        char *hostPath;
        xasprintf(&hostPath, "%s/%s", state->hostsDir, hostName);
        uint8_t *hostConfig = decode(hostEncodedConfig, config->encryptionKey, 1600);
        f = fopen(hostPath, "w");
        if (f == NULL) {
            logger(LOG_ERR, "Cannot create host file: '%s'", hostPath);
            abort();
        }
        fprintf(f, "%s\n", hostConfig);
        fclose(f);
        free(hostPath);
    }

    return state;
}

struct state *updateNetwork(cJSON *jobData, struct config *config) {
    struct state *state = NULL;
    (void) jobData;
    (void) config;

    return state;
}
