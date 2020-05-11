#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include "../xalloc.h"
#include "../logger.h"

#define KEY_BITS 4096

static int keygenIndicatorStub(int a, int b, BN_GENCB *cb) {
    (void) cb;
    (void) a;
    (void) b;
    return 1;
}

void keygen(char *configDir, char *hostsFilePath) {
    RSA *key;
    BIGNUM *bigNum = NULL;
    BN_GENCB *cb;

    cb = xmalloc_and_zero(sizeof(cb));
    if (!cb) {
        abort();
    }

    BN_GENCB_set(cb, keygenIndicatorStub, NULL);
    key = RSA_new();
    if (BN_hex2bn(&bigNum, "10001") == 0) {
        abort();
    }
    if (!key || !bigNum) {
        abort();
    }

    if (!RSA_generate_key_ex(key, KEY_BITS, bigNum, cb)) {
        logger(LOG_ERR, "Cannot generate key");
        abort();
    }
    BN_free(bigNum);
    free(cb);

    char *rsaPrivateFilePath = NULL;
    xasprintf(&rsaPrivateFilePath, "%s/rsa_key.priv", configDir);
    FILE *fPtrRsaPrivate = fopen(rsaPrivateFilePath, "w");
    if (fPtrRsaPrivate == NULL) {
        logger(LOG_ERR, "Cannot create rsa key file: '%s'", rsaPrivateFilePath);
        abort();
    }
    PEM_write_RSAPrivateKey(fPtrRsaPrivate, key, NULL, NULL, 0, NULL, NULL);
    fchmod(fileno(fPtrRsaPrivate), 0600);
    fclose(fPtrRsaPrivate);

    FILE *fPtrRsaPublic = fopen(hostsFilePath, "a");
    if (fPtrRsaPublic == NULL) {
        logger(LOG_ERR, "Cannot open host file: '%s'", hostsFilePath);
        abort();
    }
    fputc('\n', fPtrRsaPublic);
    PEM_write_RSAPublicKey(fPtrRsaPublic, key);
    fclose(fPtrRsaPublic);

    free(rsaPrivateFilePath);
    RSA_free(key);
}