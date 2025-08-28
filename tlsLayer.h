#ifndef TLSLAYER_H_
#define TLSLAYER_H_

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "session.h"
#include "debug.h"

void initMbedtls(void *arg);
err_t handhsakePoll(void *arg, tcpPcb *tpcb);
void rxBufferWrite(EchoSession *es, const uint8_t *src, size_t len);
size_t rxBufferRead(EchoSession *es, uint8_t *dst, size_t len);
size_t rxBufferAvailable(EchoSession *es);
int SSLsend(void *ctx, const unsigned char *buf, size_t len);
int SSLrecv(void *ctx, unsigned char *buf, size_t len);

#endif /* TLSLAYER_H_ */
