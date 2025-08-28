# Mbed-TLS-on-Aurix-Tricore

## Overview

This project implements a network echo application using the Gigabit Ethernet Media Access Controller (GETH) module, Lightweight IP (LwIP), and MbedTLS stacks to provide secure communication via TLS.

## Dependencies

- **OpenSSL** (client-side)
- **Aurix Tasking Toolchain**

## Hardware

- **Board:** AURIX TC375 LK (KIT_A2G_TC375_LK)

## Scope of Work

- TCP/IP protocol: Provided by LwIP
- TLS protocol: Provided by MbedTLS
- DHCP: Board obtains IP address and publishes hostname
- STM: Updates internal LwIP timers
- ASCLIN: Used for debug logging

## Hardware Setup

- Connect the board to the network via Ethernet
- Use the COM port to read debug data via USB
- Ensure PC and board are on the same network

## File Structure

```
mbedtls/include/mbedtls/config.h   - Mbed TLS configuration
mbedtls/library/entropy.c          - Update mbedtls_hardware_poll for RNG
keys.h                             - Certificates and keys
Echo.c, Echo.h                     - TCP/IP, LwIP stack
tlsLayer.c, tlsLayer.h             - TLS stack
server.crt                         - Certificate for client (use on client)
```

## Server Side Implementation

### Heap Size

- MbedTLS allocates dynamic memory (e.g., in `mbedtls_pk_parse_key()`)
- Insufficient heap may cause failures (e.g., `mbedtls_pem_read_buffer()` returns `MBEDTLS_ERR_PEM_ALLOC_FAILED`)
- Other functions like `mbedtls_ssl_setup()` also allocate memory dynamically

### Configuration File

- Location: `mbedtls/include/mbedtls/config.h`
- Enable hardware entropy: Uncomment `MBEDTLS_NO_PLATFORM_ENTROPY` and `MBEDTLS_ENTROPY_HARDWARE_ALT`
- Disable unused PSA key storage options
- Comment out unused features: `MBEDTLS_PKCS5_C`, `MBEDTLS_PKCS12_C`, `MBEDTLS_TIMING_C`, `MBEDTLS_FS_IO`, `MBEDTLS_HAVE_TIME_DATE`, `MBEDTLS_PSA_ITS_FILE_C`, `MBEDTLS_NET_C`

### Keys and Certificate

- Server keys: `keys.h`
- Client certificate: `server.crt` (copy to client)
- For security, generate your own keys and certificates

### Obtaining IP Address

- IP assigned during `Ifx_Lwip_init()` in `Cpu0_Main.c`
- Success message: `netif: new ip address assigned: XXX.XXX.X.XX` (via COM port)

### Handshake

- TLS handshake performed by polling `handhsakePoll()` (set by `tcp_poll` in LwIP)
- On success: "Handshake complete!" (debug message via COM port)

### Data Exchange

- TLS data exchange via `SSLsend()` and `SSLrecv()` (set in `tlsLayer.c`)
- These functions interact with LwIP using `tcp_write()` and `rxBufferRead()`
- `rxBufferRead()` reads payload written by `rxBufferWrite()` in `echoRecv()`

### Initialisation of lwIP

- Call `Ifx_Lwip_init()` from `Ifx_Lwip.h` to initialise lwIP

### lwIP Operation

- lwIP timers updated every millisecond by ISR (`updateLwIPStackISR()`) via STM
- Protocols (DHCP, TCP, ARP) executed by `Ifx_Lwip_pollTimerFlags()`
- Received data read by `Ifx_Lwip_pollReceiveFlags()`

### Debugging via UART

- Debug messages printed using redefined `LWIP_PLATFORM_DIAG` macro (in `Libraries/Ethernet/lwip/port/include/arch/cc.h`)
- Connect the board to the serial terminal to read debug and state messages

### Echo Application

- Application logic implemented in `Echo.c`

## Client Side Implementation

To connect to the server, run the following command on the client:

```sh
openssl s_client -connect 192.XXX.X.XX:443 -CAfile server.crt
```
The port is defined in `Echo.c`.

The `server.crt` is in the main folder of the repository.
