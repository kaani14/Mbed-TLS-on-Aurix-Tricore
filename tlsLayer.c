#include <string.h>
#include "tlsLayer.h"
#include "keys.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

void initMbedtls(void *arg) {
    LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("Initialising mbedTLS"));
    EchoSession *es = (EchoSession*) arg;

    mbedtls_ssl_init(&es->ssl);
    mbedtls_ssl_config_init(&es->conf);
    mbedtls_x509_crt_init(&es->cert);
    mbedtls_pk_init(&es->pkey);
    mbedtls_entropy_init(&es->entropy);
    mbedtls_ctr_drbg_init(&es->ctr_drbg);

    int ret;

    ret = mbedtls_ctr_drbg_seed(&es->ctr_drbg, mbedtls_entropy_func, &es->entropy, NULL, 0);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("CTR_DRBG seed failed: -0x%04X\n", -ret));
        return;
    }

    ret = mbedtls_x509_crt_parse(&es->cert, (const unsigned char *)server_cert_pem, strlen(server_cert_pem) + 1);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("Cert parse failed: -0x%04X\n", -ret));
        return;
    }

    ret = mbedtls_pk_parse_key(&es->pkey, (const unsigned char *)server_key_pem, strlen(server_key_pem) + 1, NULL, 0);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("Key parse failed: -0x%04X\n", -ret));
        return;
    }

    ret = mbedtls_ssl_config_defaults(&es->conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("Config defaults failed: -0x%04X\n", -ret));
        return;
    }

    mbedtls_ssl_conf_rng(&es->conf, mbedtls_ctr_drbg_random, &es->ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(&es->conf, &es->cert, &es->pkey);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("Conf own cert failed: -0x%04X\n", -ret));
        return;
    }

    ret = mbedtls_ssl_setup(&es->ssl, &es->conf);
    if (ret < 0) {
        LWIP_DEBUGF(LWIP_DBG_ON | LWIP_DBG_STATE,("SSL setup failed: -0x%04X\n", -ret));
        return;
    }

    es->sslInitialized = true;
    es->handshake_done = false;

    mbedtls_ssl_set_bio(&es->ssl, es, SSLsend, SSLrecv, NULL);
}


/* Poll function: it is called periodically by the TCP stack */
err_t handhsakePoll(void *arg, tcpPcb *tpcb) {
    EchoSession *es = (EchoSession *)arg;

    if (!es->handshake_done) {
        int ret = mbedtls_ssl_handshake(&es->ssl);

        if (ret == 0) {
            es->handshake_done = 1;
            tcp_poll(tpcb, NULL, 0);
            LWIP_DEBUGF(LWIP_DBG_ON| LWIP_DBG_STATE, ("Handshake complete!\n"));
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                   ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return ERR_ABRT;
        }
    }
    return ERR_OK;
}


size_t rxBufferAvailable(EchoSession *es) {
    if (es->rx_head >= es->rx_tail)
        return es->rx_head - es->rx_tail;
    else
        return sizeof(es->rx_data) - (es->rx_tail - es->rx_head);
}

size_t rxBufferRead(EchoSession *es, uint8_t *dst, size_t len) {
    size_t count = 0;
    while (count < len && es->rx_tail != es->rx_head) {
        dst[count++] = es->rx_data[es->rx_tail];
        es->rx_tail = (es->rx_tail + 1) % sizeof(es->rx_data);
    }
    return count;
}

void rxBufferWrite(EchoSession *es, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        es->rx_data[es->rx_head] = src[i];
        es->rx_head = (es->rx_head + 1) % sizeof(es->rx_data);
        if (es->rx_head == es->rx_tail) {
            es->rx_tail = (es->rx_tail + 1) % sizeof(es->rx_data);
        }
    }
}

int SSLsend(void *ctx, const unsigned char *buf, size_t len) {
    EchoSession *es = (EchoSession *)ctx;
    tcpPcb *tpcb = es->pcb;

    err_t err = tcp_write(tpcb, buf, len, 1);
    if (err == ERR_OK) {
        tcp_output(tpcb);
        return len;
    }

    if (err == ERR_MEM) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    return MBEDTLS_ERR_NET_SEND_FAILED;
}

int SSLrecv(void *ctx, unsigned char *buf, size_t len) {
    EchoSession *es = (EchoSession *)ctx;

    size_t available = rxBufferAvailable(es);
    if (available == 0) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    size_t to_copy = (available < len) ? available : len;
    size_t copied = rxBufferRead(es, buf, to_copy);

    return (int)copied;
}
