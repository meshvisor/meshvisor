#define IV_SIZE 16

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include "./../logger.h"
#include "./../xalloc.h"
#include "./../base64/base64.h"
#include "aes.h"

uint8_t *genIv() {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int i = 0;
    uint8_t *iv = xmalloc(sizeof(uint8_t) * IV_SIZE);;

    for (i = 0; i < IV_SIZE - 1; i++) {
        int key = rand() % (int) (sizeof charset - 1);
        iv[i] = charset[key];
    }
    iv[15] = '\0';

    return iv;
}

char *encodeFileByPath(char *path, uint8_t *key, int size) {
//    logger(LOG_DEBUG, "encodeFileByPath: '%s'", path);
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        logger(LOG_ERR, "encodeFileByPath: cannot open file: '%s'", path);
        abort();
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

//    logger(LOG_DEBUG, "encodeFileByPath: filesize: '%ld'", fsize);
    if (fsize + IV_SIZE > size) {
        logger(LOG_ERR, "Too big file size for encrypt");
        abort();
    }
    uint8_t *string = xmalloc(sizeof(uint8_t *) * size);

    fread(string, 1, fsize, f);
    fclose(f);
    string[fsize] = 0;
//    printf("\nSRC: %s\n", string);

    uint8_t *iv = genIv();
//    logger(LOG_DEBUG, "encodeFileByPath: Iv: '%s'", iv);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, string, size);
//    printf("\nENC: %s\n", (char *) string);

    char *base64str = xmalloc(sizeof(char *) * size);
    bintob64(base64str, string, size);

    char *base64WithIv;
    xasprintf(&base64WithIv, "%s%s", iv, base64str);
//    printf("\nBASE64: %s\n", base64str);


//    uint8_t *iv2 = xmalloc(sizeof(uint8_t *) * IV_SIZE);
//    memmove(iv2, base64WithIv, IV_SIZE);
//    int stringSize = sizeof(char *) * strlen(base64WithIv);
//    char *base64str2 = xmalloc(stringSize);
//    logger(LOG_DEBUG, "encodeFileByPath: string size: '%d'", stringSize);
//    memmove(base64str2, base64WithIv + IV_SIZE - 1, stringSize);
//    printf("\nBASE64: %s\n", base64str2);
//
//    uint8_t *result2 = xmalloc(sizeof(uint8_t *) * size);
//    b64tobin(result2, base64str2);
//    struct AES_ctx ctx2;
//    iv2[15] = '\0';
//    logger(LOG_DEBUG, "encodeFileByPath: iv: '%s'", iv);
//    logger(LOG_DEBUG, "encodeFileByPath: iv2: '%s'", iv2);
//    AES_init_ctx_iv(&ctx2, key, iv2);
//    AES_CTR_xcrypt_buffer(&ctx2, result2, size);
//    printf("\nDEC: %s\n", (char *) result2);
//
//    free(iv2);
//    free(base64str2);
//    free(result2);

    free(iv);
    free(string);
    free(base64str);

    return base64WithIv;
}

uint8_t *decode(char *string, uint8_t *key, int size) {
    (void)key;
    (void)size;

    uint8_t *iv = xmalloc(sizeof(uint8_t *) * IV_SIZE);
//    logger(LOG_DEBUG, "decode: string: '%s'", string);
    memmove(iv, string, IV_SIZE);
//    logger(LOG_DEBUG, "decode: iv: '%s'", (char *) iv);
    iv[15] = '\0';

    int base64strSize = sizeof(char *) * strlen(string);
    char *base64str = xmalloc(base64strSize);
    memmove(base64str, string + IV_SIZE-1, base64strSize);
//    logger(LOG_DEBUG, "decode: base64str: '%s'", base64str);
    uint8_t *result = xmalloc(sizeof(uint8_t *) * size);
    b64tobin(result, base64str);
//    int enc2Len = strlen((char *) result);
//    logger(LOG_DEBUG, "encodeFileByPath: string length after base64decode: '%d'", enc2Len);
//    printf("\nENC2: %s\n", (char *) result);
//
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, result, size);
//    printf("\nDEC: %s\n", (char *) result);

    free(iv);
    free(base64str);

    return result;
}