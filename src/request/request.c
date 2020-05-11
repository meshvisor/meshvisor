//#define UNUSED(x) (void)(x)

#include <stdlib.h>
#include <curl/curl.h>
#include "src/cJSON/cJSON.h"
#include <stdbool.h>
#include "../conf.h"
#include "../logger.h"
#include "../xalloc.h"
#include "request.h"

struct request *requestInit(struct config *config, char *url) {
    struct request *request = xmalloc(sizeof(struct request));
    char *authorization = NULL;
    struct curl_slist *headers = NULL;

    request->query = NULL;
    request->post = NULL;
    request->url = url;
    request->curl = curl_easy_init();
    if (!request->curl) {
        logger(LOG_ERR, "Cannot init curl");
        abort();
    }
    xasprintf(&authorization, "Authorization: Bearer %s", config->accessToken);
    headers = curl_slist_append(headers, authorization);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(request->curl, CURLOPT_URL, url);
    curl_easy_setopt(request->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(request->curl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_easy_setopt(request->curl, CURLOPT_TIMEOUT, 15);
//    curl_easy_setopt(request->curl, CURLOPT_PROXY, "http://127.0.0.1:7080");//@TODO
    curl_easy_setopt(request->curl, CURLOPT_HTTPHEADER, headers);

//    free(authorization);
//    free(headers);

    return request;
}

void requestSetQuery(struct request *request, char *query) {
    request->query = query;
}

void requestSetPostParams(struct request *request, char *name, int type, char *value) {
    cJSON *item = NULL;
    bool boolValue = NULL;

    if (!request->post) {
        request->post = cJSON_CreateObject();
        if (!request->post) {
            logger(LOG_ERR, "Create postJson memory error");
            abort();
        }
    }

    switch (type) {
        case PARAM_BOOL:
            boolValue = true;
            if (!strcmp(value, "0")) {
                boolValue = false;
            }
            cJSON_AddBoolToObject(request->post, name, boolValue);
            item = cJSON_GetObjectItemCaseSensitive(request->post, name);
            if (!item/* @TODO || item != false*/) {
                logger(LOG_ERR, "Create postJson bool property memory error");
                abort();
            }
            break;
        case PARAM_STRING:
            item = cJSON_AddStringToObject(request->post, name, value);
            if (!item || strcmp(item->valuestring, value)) {
                logger(LOG_ERR, "Create postJson string property memory error");
                abort();
            }
            break;
        default:
            logger(LOG_ERR, "Unknown parameter type '%d'", type);
            abort();
    }
}

struct CurlMemoryStruct {
    char *memory;
    size_t size;
};

static size_t requestWrite(void *data, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct CurlMemoryStruct *mem = (struct CurlMemoryStruct *) userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);

    if (ptr == NULL) {
        abort();
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), data, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

cJSON *sendRequest(struct request *request) {
    CURLcode res;
    long http_code = 0;
    struct CurlMemoryStruct chunk;

    char *url;
    if (NULL != request->query) {
        xasprintf(&url, "%s?%s", request->url, request->query);
    } else {
        url = request->url;
    }
    curl_easy_setopt(request->curl, CURLOPT_URL, url);
    logger(LOG_DEBUG, "Request %s", url);

    chunk.memory = malloc(1);
    chunk.size = 0;

    if (request->post) {
        char *postJsonStr = cJSON_PrintUnformatted(request->post);
        if (!postJsonStr) {
            logger(LOG_ERR, "Error generation postJsonStr");
            abort();
        }
        curl_easy_setopt(request->curl, CURLOPT_POSTFIELDS, postJsonStr);
    } else {
        logger(LOG_DEBUG, "Request set GET");
        curl_easy_setopt(request->curl, CURLOPT_HTTPGET, 1L);
    }
    curl_easy_setopt(request->curl, CURLOPT_WRITEFUNCTION, requestWrite);
    curl_easy_setopt(request->curl, CURLOPT_WRITEDATA, (void *) &chunk);

    res = curl_easy_perform(request->curl);
    if (res != CURLE_OK) {
        logger(LOG_ERR, "Request error(%d): %s", res, curl_easy_strerror(res));
    } else {
        curl_easy_getinfo (request->curl, CURLINFO_RESPONSE_CODE, &http_code);
        switch (http_code) {
            case 200:
                logger(LOG_DEBUG, chunk.memory);
                return cJSON_Parse(chunk.memory);
            case 400:
                //@TODO show errors
                logger(LOG_ERR, "Request client error");
                break;
            case 401:
                logger(LOG_ERR, "Request client error: Not Authorized, check accessToken");
                break;
            default:
                logger(LOG_ERR, "Request error. Code: %ld", http_code);
        }
    }
//    curl_easy_cleanup(request->curl);
    free(chunk.memory);
//    curl_global_cleanup();

    return NULL;
}