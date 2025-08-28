#ifndef SESSION_H_
#define SESSION_H_

#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include <stdbool.h>

#define STORAGE_SIZE_BYTES 256


typedef struct tcp_pcb tcpPcb;
typedef struct pbuf pBuf;

typedef struct{
    u8_t state;
    tcpPcb *pcb;
    pBuf *p;
    char storage[STORAGE_SIZE_BYTES];
    uint16 nextFreeStoragePos;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    bool sslInitialized;
    bool handshake_done;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;

    // TCP receive buffer for mbedTLS
    uint8_t rx_data[2048];
    size_t rx_head;
    size_t rx_tail;
} EchoSession;

#endif /* SESSION_H_ */
