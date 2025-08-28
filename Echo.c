#include <string.h>
#include <stdio.h>

#include "Echo.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "tlsLayer.h"
#include "session.h"

#define STORAGE_SIZE_BYTES 256
#define RX_BUFFER_SIZE 2048

enum EchoStates
{
    ES_NONE = 0,
    ES_ACCEPTED,
    ES_RECEIVING,
    ES_CLOSING
};

tcpPcb *g_echoPcb;

err_t echoAccept (void *arg, tcpPcb *newPcb, err_t err);
err_t echoRecv (void *arg, tcpPcb *tpcb, pBuf *p, err_t err);
void echoError (void *arg, err_t err);
err_t echoPoll (void *arg, tcpPcb *tpcb);
err_t echoSent (void *arg, tcpPcb *tpcb, u16_t len);
void echoSend (tcpPcb *tPcb, EchoSession *es);
void echoUnpack (tcpPcb *tPcb, EchoSession *es);
void echoClose (tcpPcb *tPcb, EchoSession *es);

void echoInit(void)
{
    g_echoPcb = tcp_new();
    if (g_echoPcb != NULL)
    {
        err_t err = tcp_bind(g_echoPcb, IP_ADDR_ANY, 443);
        if (err == ERR_OK)
        {
            g_echoPcb = tcp_listen(g_echoPcb);
            tcp_accept(g_echoPcb, echoAccept);
        }
        else
        {
            LWIP_DEBUGF(ECHO_DEBUG | LWIP_DBG_STATE, ("Echo: unable to bind to any address on port 443.\n"));
        }
    }
    else
    {
        LWIP_DEBUGF(ECHO_DEBUG | LWIP_DBG_STATE, ("Echo: unable to create a TCP control block.\n"));
    }
}

/* Accept callback: it is called every time a client establish a new connection */
err_t echoAccept(void *arg, tcpPcb *newPcb, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    err_t retErr;
    EchoSession *es = (EchoSession*) mem_malloc(sizeof(EchoSession));
    initMbedtls(es);

    if (es != NULL)
    {
        es->state = ES_ACCEPTED;
        es->pcb = newPcb;
        es->p = NULL;
        memset(es->storage, 0, STORAGE_SIZE_BYTES);
        es->nextFreeStoragePos = 0;

        tcp_arg(newPcb, es);
        tcp_recv(newPcb, echoRecv);
        tcp_sent(newPcb, echoSent);
        tcp_err(newPcb, echoError);
        tcp_poll(newPcb, echoPoll, 0);
        retErr = ERR_OK;

    }
    else
    {
        retErr = ERR_MEM;
    }
    return retErr;
}


/* Recv callback: it is called every time data is received through the TCP connection */
err_t echoRecv(void *arg, tcpPcb *tpcb, pBuf *p, err_t err) {
    EchoSession *es = (EchoSession*) arg;

    if (p == NULL) {
        return ERR_OK;
    }

    // Store raw TCP data
    rxBufferWrite(es, p->payload, p->len);
    tcp_recved(tpcb, p->len);
    pbuf_free(p);

    if (!es->handshake_done) {
        tcp_poll(tpcb, handhsakePoll, 2);
    } else {

        // Decryption
        unsigned char buf[512];
        int ret = mbedtls_ssl_read(&es->ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
            buf[ret] = '\0';  // Null-terminate received data

            char reply[600];  // Enough space for "Board: " + received data
            int reply_len = snprintf(reply, sizeof(reply), "Board: %s", buf);

            mbedtls_ssl_write(&es->ssl, (const unsigned char*)reply, reply_len);
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // Non-blocking continuation, no action needed
        }
        else {
            // Error or connection closed
        }
    }
    return ERR_OK;
}

/* Error callback: it is called if a fatal error has already occurred on the connection */
void echoError(void *arg, err_t err)
{
    LWIP_UNUSED_ARG(err);

    EchoSession *es = (EchoSession*) arg;

    if (es != NULL)
    {
        mem_free(es);
    }
}


/* Poll function: it is called periodically by the TCP stack */
err_t echoPoll(void *arg, tcpPcb *tpcb)
{
    err_t retErr;
    EchoSession *es = (EchoSession*) arg;

    if (es != NULL)
    {
        if (es->p != NULL ||
            es->nextFreeStoragePos != 0)
        {
            echoUnpack(tpcb, es);
            echoSend(tpcb, es);
        }
        else
        {
            if (es->state == ES_CLOSING)
            {
                echoClose(tpcb, es);
            }
        }
        retErr = ERR_OK;
    }
    else
    {
        tcp_abort(tpcb);
        retErr = ERR_ABRT;
    }
    return retErr;
}

/* Sent callback: it is called when TCP data has successfully been delivered to the remote host */
err_t echoSent(void *arg, tcpPcb *tpcb, u16_t len)
{
    LWIP_UNUSED_ARG(len);

    EchoSession *es = (EchoSession*) arg;

    if (es->p != NULL )
    {
        echoUnpack(tpcb, es);
        echoSend(tpcb, es);
    }
    else
    {
        if (es->state == ES_CLOSING)
        {
            echoClose(tpcb, es);
        }
    }
    return ERR_OK;
}

/* Send function: enqueues TCP data to be delivered to the remote client */
void echoSend(tcpPcb *tpcb, EchoSession *es)
{
    if(es->nextFreeStoragePos == 0)
    {
        return;
    }
    if(es->storage[es->nextFreeStoragePos - 1] != '\n' &&
       es->nextFreeStoragePos < STORAGE_SIZE_BYTES)
    {
        return;
    }
    err_t wrErr = tcp_write(tpcb, "Board: ", 7, 1);
    wrErr |= tcp_write(tpcb, es->storage, es->nextFreeStoragePos, 1);
    if(wrErr == ERR_OK)
    {
        es->nextFreeStoragePos = 0;
    }
}

/* Unpack function: dequeues data from the package buffer and copies it in the session storage */
void echoUnpack(tcpPcb *tpcb, EchoSession *es)
{
    pBuf *ptr;

    while ((es->p != NULL))
    {
        ptr = es->p;

        if (es->nextFreeStoragePos + ptr->len <= STORAGE_SIZE_BYTES)
        {
            memcpy(&es->storage[es->nextFreeStoragePos],
                    ptr->payload,
                    ptr->len);
            es->nextFreeStoragePos += ptr->len;

            u16_t plen = ptr->len;

            es->p = ptr->next;
            if (es->p != NULL)
            {
                pbuf_ref(es->p);
            }

            u8_t freed;
            do
            {
                freed = pbuf_free(ptr);
            } while (freed == 0);

            tcp_recved(tpcb, plen);
        }
    }
}

/* Close function: closes a TCP connection and deallocates session resources */
void echoClose(tcpPcb *tpcb, EchoSession *es)
{
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, NULL, 0);

    if (es != NULL)
    {
        mem_free(es);
    }
    tcp_close(tpcb);
}
