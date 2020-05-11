#define UNUSED(x) (void)(x)
#define DOMAIN "api.meshvisor.wip"
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

void initNetwork(cJSON *jobData, struct config *config);
void updateNetwork(cJSON *jobData, struct config *config);

bool sendHostKey(struct config *config, char *encodedHost);

void saveState(struct config *config, double stateNumber);

void daemonMain(pid_t tincStarterPid, struct config *config);

static void sigchldHandler() {
    fprintf(stderr, "Daemon: TincStarter down\n");
    abort();
}

int main() {
    srand(time(NULL));
    struct config *config = parseUserConfig();

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
        if(!write_pid(config->pidMeshvisorFilePath)) {
            fprintf(stderr, "Daemon: Couldn't write pid file %s: %s\n", config->pidMeshvisorFilePath, strerror(errno));
            abort();
        }
        struct sigaction sa;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sa.sa_handler = sigchldHandler;
        sigaction(SIGCHLD, &sa, NULL);
        daemonMain(forkPid, config);
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
void daemonMain(pid_t tincStarterPid, struct config *config) {
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
        xasprintf(&getJobQuery, "state_number=%d", config->stateNumber);
        requestSetQuery(getJobRequest, getJobQuery);
        cJSON *getJobResponse = sendRequest(getJobRequest);
        if (NULL != getJobResponse) {
            if (!cJSON_HasObjectItem(getJobResponse, "job")) {
                logger(LOG_ERR, "Unexpected getJobResponse: Property 'job' isn't exists");
            } else if (!cJSON_HasObjectItem(getJobResponse, "data")) {
                logger(LOG_ERR, "Unexpected getJobResponse: Property 'data' isn't exists");
            } else {
                char *job = cJSON_GetObjectItem(getJobResponse, "job")->valuestring;
                cJSON *jobData = cJSON_GetObjectItem(getJobResponse, "data");
                if (!strcmp(job, "nothingToDo")) {
                    if (!isTincStarted) {
                        isTincStarted = startTinc(tincStarterPid);
                    }
                } else if (!strcmp(job, "init")) {
                    initNetwork(jobData, config);
                    char *encodedHost = encodeFileByPath(config->hostsFilePath, config->encryptionKey, 1600);
                    if (sendHostKey(config, encodedHost)) {
                        double stateNumber = cJSON_GetObjectItem(jobData, "stateNumber")->valueint;
                        saveState(config, stateNumber);
                    }
                    free(encodedHost);
                    logger(LOG_DEBUG, "Daemon: Send SIGUSR1 to Tink Starter");
                    isTincStarted = startTinc(tincStarterPid);
                } else if (!strcmp(job, "update")) {
                    updateNetwork(jobData, config);
                    double stateNumber = cJSON_GetObjectItem(jobData, "stateNumber")->valueint;
                    saveState(config, stateNumber);
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
        }
        logger(LOG_DEBUG, "Sleep %d", config->poolingRate);
        sleep(config->poolingRate);
    }
}

void saveState(struct config *config, double stateNumber) {
    cJSON *state = cJSON_CreateObject();
    cJSON *item = cJSON_AddNumberToObject(state, "number", stateNumber);
    if (!item || item->valueint != stateNumber) {
        logger(LOG_ERR, "Create postJson string property memory error");
        abort();
    }
    char *jsonStr = cJSON_PrintUnformatted(state);
    if (!jsonStr) {
        logger(LOG_ERR, "Error generation postJsonStr");
        abort();
    }
    FILE *fPtrTincConf = fopen(config->stateFilePath, "w");
    if (fPtrTincConf == NULL) {
        logger(LOG_ERR, "Cannot create tinc config file: '%s'", config->tincConfPath);
        abort();
    }
    fprintf(fPtrTincConf, jsonStr);
    fclose(fPtrTincConf);
    config->stateNumber = stateNumber;
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

void initNetwork(cJSON *jobData, struct config *config) {
    cJSON *iterator = NULL;
    FILE *f = NULL;

    logger(LOG_INFO, "Start network init job");
    char *nodeName = cJSON_GetObjectItem(jobData, "name")->valuestring;
    cJSON *network = cJSON_GetObjectItem(jobData, "network");
    char *networkName = cJSON_GetObjectItem(network, "name")->valuestring;
    char *networkInternalIp = cJSON_GetObjectItem(network, "internalIp")->valuestring;
    char *networkInternalMask = cJSON_GetObjectItem(network, "internalMask")->valuestring;
    char *networkNodeSubnet = cJSON_GetObjectItem(network, "nodeSubnet")->valuestring;
    char *networkExternalIp = cJSON_GetObjectItem(network, "externalIp")->valuestring;
    char *addressFamily = cJSON_GetObjectItem(jobData, "addressFamily")->valuestring;
    cJSON *connectTo = cJSON_GetObjectItem(jobData, "connectTo");
    logger(LOG_INFO, "Network name: '%s'; Node name: '%s';", networkName, nodeName);
    setConfigPaths(config, networkName, nodeName);
    logger(LOG_DEBUG, "Remove config folder '%s' if exists", config->configDir);
    nftw(config->configDir, unlinkCb, 64, FTW_DEPTH | FTW_PHYS);
    logger(LOG_DEBUG, "Create config folders");
    mkdir(config->networkDir, 0755);
    mkdir(config->configDir, 0755);
    mkdir(config->hostsDir, 0755);

    f = fopen(config->tincConfPath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc config file: '%s'", config->tincConfPath);
        abort();
    }
    fprintf(f, "Name = %s\n", nodeName);
    fprintf(f, "AddressFamily = %s\n", addressFamily);
    fprintf(f, "Interface = %s\n", config->interface);
    cJSON_ArrayForEach(iterator, connectTo) {
        fprintf(f, "ConnectTo = %s\n", iterator->valuestring);
    }
    fclose(f);

    f = fopen(config->hostsFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create host file: '%s'", config->hostsFilePath);
        abort();
    }
    if (NULL != networkExternalIp) {
        fprintf(f, "Address = %s\n", networkExternalIp);
    }
    fprintf(f, "Subnet = %s\n", networkNodeSubnet);
    fclose(f);
    logger(LOG_DEBUG, "Generate keys");
    keygen(config->configDir, config->hostsFilePath);

    f = fopen(config->tincUpFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc-up file: '%s'", config->tincUpFilePath);
        abort();
    }
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "ifconfig $INTERFACE %s netmask %s\n", networkInternalIp, networkInternalMask);
    fclose(f);

    f = fopen(config->tincDownFilePath, "w");
    if (f == NULL) {
        logger(LOG_ERR, "Cannot create tinc-down file: '%s'", config->tincDownFilePath);
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
        xasprintf(&hostPath, "%s/%s", config->hostsDir, hostName);
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
}

void updateNetwork(cJSON *jobData, struct config *config) {
    (void)jobData;
    (void)config;
}
