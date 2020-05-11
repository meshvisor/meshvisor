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
    char *configDir;
    char *tincConfPath;
    char *hostsDir;
    char *hostsFilePath;
    char *stateFilePath;
    char *tincUpFilePath;
    char *tincDownFilePath;
    int stateNumber;
};

struct config *parseUserConfig();
void setConfigPaths(struct config *config, char *networkName, char *nodeName);
