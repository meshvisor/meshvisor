#define PARAM_STRING 1
#define PARAM_BOOL 2

struct request {
    CURL *curl;
    char *url;
    char *query;
    cJSON *post;
};

struct request *requestInit(struct config *config, char *url);
void requestSetQuery(struct request *request, char *query);
void requestSetPostParams(struct request *request, char *name, int type, char *value);
//void requestSetData(CURL *curl, char post[][3][16], size_t size);
cJSON *sendRequest(struct request *request);
