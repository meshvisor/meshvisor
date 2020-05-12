#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "src/cJSON/cJSON.h"
#include "conf.h"
#include "logger.h"
#include "xalloc.h"
#include "ini/src/ini.h"

struct state *parseStateFileIfExists(struct config *config) {
    FILE *f = fopen(config->stateFilePath, "rb");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *string = xmalloc(sizeof(char *) * fsize);
        fread(string, 1, fsize, f);
        fclose(f);

        cJSON *json = cJSON_Parse(string);
        return createState(
                config,
                cJSON_GetObjectItem(json, "number")->valueint,
                cJSON_GetObjectItem(json, "network")->valuestring,
                cJSON_GetObjectItem(json, "node")->valuestring
        );
    }

    return NULL;
}

struct state *createState(struct config *config, int number, char *network, char *node) {
    struct state *state = xmalloc(sizeof(struct state));

    state->number = number;
    state->network = network;
    state->node = node;
    xasprintf(&state->configDir, "%s/%s", config->networkDir, state->network);
    xasprintf(&state->tincConfPath, "%s/tinc.conf", state->configDir);
    xasprintf(&state->hostsDir, "%s/hosts", state->configDir);
    xasprintf(&state->hostsFilePath, "%s/%s", state->hostsDir, state->node);
    xasprintf(&state->tincUpFilePath, "%s/tinc-up", state->configDir);
    xasprintf(&state->tincDownFilePath, "%s/tinc-down", state->configDir);

    return state;
}

void dumpState(struct config *config, struct state *state) {
    cJSON *json = cJSON_CreateObject();
    cJSON *item = cJSON_AddNumberToObject(json, "number", state->number);
    if (!item || item->valueint != state->number) {
        logger(LOG_ERR, "Create postJson string property memory error");
        abort();
    }
    item = cJSON_AddStringToObject(json, "network", state->network);
    if (!item || strcmp(item->valuestring, state->network)) {
        logger(LOG_ERR, "Create postJson string property memory error");
        abort();
    }
    item = cJSON_AddStringToObject(json, "node", state->node);
    if (!item || strcmp(item->valuestring, state->node)) {
        logger(LOG_ERR, "Create postJson string property memory error");
        abort();
    }

    char *jsonStr = cJSON_PrintUnformatted(json);
    if (!jsonStr) {
        logger(LOG_ERR, "Error generation postJsonStr");
        abort();
    }
    FILE *fPtrTincConf = fopen(config->stateFilePath, "w");
    if (fPtrTincConf == NULL) {
        logger(LOG_ERR, "Cannot create state file: '%s'", state->tincConfPath);
        abort();
    }
    fprintf(fPtrTincConf, jsonStr);
    fclose(fPtrTincConf);
}

struct config *parseUserConfig() {
    struct config *config = xmalloc(sizeof(struct config));

    ini_t *cfg = ini_load( ETCDIR "/meshvisor.conf");
    if (NULL == cfg) {
        fprintf(stderr, "Cannot read config file %s/meshvisor.conf\n", ETCDIR);
        abort();
    }

    config->accessToken = ini_get(cfg, "main", "accessToken");
    if (NULL == config->accessToken) {
        fprintf(stderr, "Config property \"accessToken\" not exists\n");
    }

    const char *encryptionKey = ini_get(cfg, "main", "encryptionKey");
    if (NULL == encryptionKey) {
        fprintf(stderr, "Config property \"encryptionKey\" not exists\n");
    }
    config->encryptionKey = (uint8_t *) encryptionKey;

    config->interface = ini_get(cfg, "main", "interface");
    if (NULL == config->interface) {
        fprintf(stderr, "Config property \"interface\" not exists\n");
    }

    config->interface = ini_get(cfg, "main", "interface");
    if (NULL == config->interface) {
        fprintf(stderr, "Config property \"interface\" not exists\n");
    }

    const char *poolingRate = ini_get(cfg, "main", "poolingRate");
    if (NULL == poolingRate) {
        fprintf(stderr, "Config property \"poolingRate\" not exists\n");
    }
    config->poolingRate = atoi(poolingRate);

    ini_free(cfg);

    xasprintf(&config->pidMeshvisorFilePath, "%s/meshvisor.pid", RUNDIR);
    xasprintf(&config->pidStarterFilePath, "%s/tincStarter.pid", RUNDIR);
    xasprintf(&config->pidTincFilePath, "%s/tinc.pid", RUNDIR);
    xasprintf(&config->networkDir, "%s/network", LIBDIR);
    xasprintf(&config->stateFilePath, "%s/%s", LIBDIR, "state.json");

    return config;
}