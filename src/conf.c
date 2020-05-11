#include <libconfig.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cjson/cJSON.h>
#include "conf.h"
#include "logger.h"
#include "xalloc.h"

void parseStateFileIfExists(struct config *config) {
    FILE *f = fopen(config->stateFilePath, "rb");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *string = xmalloc(sizeof(char *) * fsize);
        fread(string, 1, fsize, f);
        fclose(f);

        cJSON *json = cJSON_Parse(string);
        if (!cJSON_HasObjectItem(json, "number")) {
            logger(LOG_ERR, "Unexpected state: Property 'number' isn't exists");
            abort();
        }
        config->stateNumber = cJSON_GetObjectItem(json, "number")->valueint;
    } else {
        config->stateNumber = 0;
        logger(LOG_DEBUG, "State file not exists: '%s'", config->stateFilePath);
    }
}

struct config *parseUserConfig() {
    struct config *config = xmalloc(sizeof(struct config));
    config_t cfg;
    const char *str;

    config_init(&cfg);
    if (!config_read_file(&cfg, ETCDIR "/meshvisor.conf")) {
        if (NULL == config_error_file(&cfg)) {
            logger(LOG_ERR, "Cannot read config file %s/meshvisor.conf", ETCDIR);
        } else {
            logger(LOG_ERR, "%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        }
        abort();
    } else {
        if (!config_lookup_string(&cfg, "accessToken", &str)) {
            logger(LOG_ERR, "Config property \"accessToken\" not exists");
            abort();
        } else {
            config->accessToken = xstrdup(str);
        }
        if (!config_lookup_string(&cfg, "encryptionKey", &str)) {
            logger(LOG_ERR, "Config property \"encryptionKey\" not exists");
            abort();
        } else {
            config->encryptionKey = (uint8_t *) xstrdup(str);
        }
        if (!config_lookup_string(&cfg, "interface", &str)) {
            logger(LOG_ERR, "Config property \"interface\" not exists");
            abort();
        } else {
            config->interface = xstrdup(str);
        }
//        if (!config_lookup_int(&cfg, "poolingRate", config->poolingRate)) {
//            logger(LOG_ERR, "Config property \"poolingRate\" not exists");
//            abort();
//        }
        config->poolingRate = 3;
    }
    config_destroy(&cfg);

    xasprintf(&config->pidMeshvisorFilePath, "%s/meshvisor.pid", RUNDIR);
    xasprintf(&config->pidStarterFilePath, "%s/tincStarter.pid", RUNDIR);
    xasprintf(&config->pidTincFilePath, "%s/tinc.pid", RUNDIR);
    xasprintf(&config->networkDir, "%s/network", LIBDIR);
    xasprintf(&config->stateFilePath, "%s/%s", LIBDIR, "state.json");

    parseStateFileIfExists(config);

    return config;
}

void setConfigPaths(struct config *config, char *networkName, char *nodeName) {
    xasprintf(&config->configDir, "%s/%s", config->networkDir, networkName);
    xasprintf(&config->tincConfPath, "%s/tinc.conf", config->configDir);
    xasprintf(&config->hostsDir, "%s/hosts", config->configDir);
    xasprintf(&config->hostsFilePath, "%s/%s", config->hostsDir, nodeName);
    xasprintf(&config->tincUpFilePath, "%s/tinc-up", config->configDir);
    xasprintf(&config->tincDownFilePath, "%s/tinc-down", config->configDir);
}