#include <stdbool.h>
#include <stdint.h>

struct config {
	const char *accessToken;
	uint8_t *encryptionKey;
    int poolingRate;
    const char *interface;
    char *networkDir;
    char *pidMeshvisorFilePath;
    char *pidStarterFilePath;
    char *pidTincFilePath;
    char *stateFilePath;
};

struct state {
    int number;
    char *network;
    char *node;
    char *configDir;
    char *tincConfPath;
    char *hostsDir;
    char *hostsFilePath;
    char *tincUpFilePath;
    char *tincDownFilePath;
};

struct config *parseUserConfig();
struct state *parseStateFileIfExists(struct config *config);
struct state *createState(struct config *config, int number, char *network, char *node);
void dumpState(struct config *config, struct state *state);