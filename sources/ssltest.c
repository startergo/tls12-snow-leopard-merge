/*
 * ssltest.c — TLS client smoke test for Snow Leopard libsecurity_ssl-55002
 * v4: verbose per-record tracing using SSLGetBufferedReadSize to detect
 *     how far into the handshake we get before errSSLProtocol fires.
 *
 * Compile against patched dylib (direct link):
 *   gcc -std=c99 -o /tmp/ssltest_direct /tmp/ssltest.c \
 *       /tmp/libsecurity_ssl_tls12.dylib \
 *       -framework CoreFoundation \
 *       -mmacosx-version-min=10.6 -arch x86_64
 *
 * Compile against stock Security (baseline):
 *   gcc -std=c99 -o /tmp/ssltest_stock /tmp/ssltest.c \
 *       -framework Security -framework CoreFoundation \
 *       -mmacosx-version-min=10.6 -arch x86_64
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <Security/SecureTransport.h>

#define kTLSProtocol11  ((SSLProtocol)7)
#define kTLSProtocol12  ((SSLProtocol)8)

#define CONNECT_TIMEOUT_SEC  10
#define OVERALL_TIMEOUT_SEC  25

/* ── verbose I/O wrappers that log each read/write ─────────────────── */
typedef struct { int fd; int verbose; } Conn;

static volatile int g_read_count  = 0;
static volatile int g_write_count = 0;

static OSStatus ssl_read(SSLConnectionRef conn, void *data, size_t *len)
{
    Conn *c = (Conn *)(intptr_t)conn;
    ssize_t n = read(c->fd, data, *len);
    if (n > 0) {
        if (c->verbose) fprintf(stderr, "  [io] read  #%d: %zd bytes\n", ++g_read_count, n);
        *len = (size_t)n; return noErr;
    }
    if (n == 0) { *len = 0; return errSSLClosedGraceful; }
    *len = 0;
    return (errno == EAGAIN) ? errSSLWouldBlock : errSSLClosedAbort;
}

static OSStatus ssl_write(SSLConnectionRef conn, const void *data, size_t *len)
{
    Conn *c = (Conn *)(intptr_t)conn;
    ssize_t n = write(c->fd, data, *len);
    if (n >= 0) {
        if (c->verbose) fprintf(stderr, "  [io] write #%d: %zd bytes\n", ++g_write_count, n);
        *len = (size_t)n; return noErr;
    }
    *len = 0;
    return (errno == EAGAIN) ? errSSLWouldBlock : errSSLClosedAbort;
}

static void alarm_handler(int sig) {
    (void)sig;
    fprintf(stderr, "TIMEOUT after %d seconds\n", OVERALL_TIMEOUT_SEC);
    exit(2);
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res, *r;
    int fd = -1, flags, rc;
    fd_set wset;
    struct timeval tv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        rc = connect(fd, r->ai_addr, r->ai_addrlen);
        if (rc == 0) { fcntl(fd, F_SETFL, flags); break; }
        if (errno == EINPROGRESS) {
            FD_ZERO(&wset); FD_SET(fd, &wset);
            tv.tv_sec = CONNECT_TIMEOUT_SEC; tv.tv_usec = 0;
            rc = select(fd + 1, NULL, &wset, NULL, &tv);
            if (rc > 0) {
                int soerr = 0; socklen_t solen = sizeof soerr;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &solen);
                if (soerr == 0) { fcntl(fd, F_SETFL, flags); break; }
            }
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static const char *ssl_errstr(OSStatus err) {
    switch (err) {
        case -9800: return "errSSLProtocol";
        case -9801: return "errSSLNegotiation";
        case -9802: return "errSSLFatalAlert";
        case -9806: return "errSSLClosedAbort";
        case -9810: return "errSSLDecryptionFail";
        case -9811: return "errSSLBadRecordMac";
        case -9812: return "errSSLRecordOverflow";
        case -9820: return "errSSLBufferOverflow";
        case -9821: return "errSSLBadCipherSuite";
        case -9824: return "errSSLPeerHandshakeFail";
        case -9826: return "errSSLPeerProtocolVersion";
        case -9845: return "errSSLPeerBadRecordMac";
        case -9847: return "errSSLPeerDecryptionFail";
        case -9853: return "errSSLPeerInternalError";
        case -9862: return "errSSLPeerDecodeError";
        default:    return "unknown";
    }
}

static const char *prot_string(SSLProtocol p) {
    switch ((int)p) {
        case 2: return "SSL 2.0"; case 3: return "SSL 3.0";
        case 4: return "TLS 1.0"; case 7: return "TLS 1.1";
        case 8: return "TLS 1.2"; default: return "unknown";
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "usage: ssltest <host> <port> [max_proto_enum] [-v]\n");
        return 1;
    }
    const char *host = argv[1];
    const char *port = argv[2];
    SSLProtocol forceMaxProt = kTLSProtocol12;
    int verbose = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else forceMaxProt = (SSLProtocol)atoi(argv[i]);
    }

    signal(SIGALRM, alarm_handler);
    alarm(OVERALL_TIMEOUT_SEC);

    int rawfd = tcp_connect(host, port);
    if (rawfd < 0) { fprintf(stderr, "TCP connect failed\n"); return 1; }
    printf("TCP connected to %s:%s\n", host, port);

    Conn conn = { rawfd, verbose };

    SSLContextRef ctx;
    OSStatus err = SSLNewContext(false, &ctx);
    if (err) { fprintf(stderr, "SSLNewContext: %d\n", (int)err); close(rawfd); return 1; }

    SSLSetIOFuncs(ctx, ssl_read, ssl_write);
    SSLSetConnection(ctx, (SSLConnectionRef)&conn);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    SSLSetEnableCertVerify(ctx, false);

    {
        size_t n = 0;
        SSLGetNumberEnabledCiphers(ctx, &n);
        printf("Enabled cipher count: %zu\n", n);
    }

    if (forceMaxProt != kTLSProtocol12) {
        printf("Forcing max protocol to enum %d\n", (int)forceMaxProt);
        SSLSetProtocolVersionEnabled(ctx, kSSLProtocolAll, false);
        SSLSetProtocolVersionEnabled(ctx, kSSLProtocol3, true);
        SSLSetProtocolVersionEnabled(ctx, kTLSProtocol1, true);
        if (forceMaxProt >= kTLSProtocol11) SSLSetProtocolVersionEnabled(ctx, kTLSProtocol11, true);
        if (forceMaxProt >= kTLSProtocol12) SSLSetProtocolVersionEnabled(ctx, kTLSProtocol12, true);
    }

    printf("Starting TLS handshake (verbose I/O: %s)...\n", verbose ? "yes" : "no");
    fflush(stdout);

    do { err = SSLHandshake(ctx); } while (err == errSSLWouldBlock);

    alarm(0);

    SSLProtocol negotiated = kSSLProtocolUnknown;
    SSLGetNegotiatedProtocolVersion(ctx, &negotiated);
    SSLCipherSuite cipher = 0;
    SSLGetNegotiatedCipher(ctx, &cipher);

    if (err != noErr) {
        fprintf(stderr, "SSLHandshake failed: %d (%s)\n", (int)err, ssl_errstr(err));
        fprintf(stderr, "  reads=%d  writes=%d\n", g_read_count, g_write_count);
        if (negotiated != kSSLProtocolUnknown)
            fprintf(stderr, "  partial negotiation: %s  cipher=0x%04X\n",
                prot_string(negotiated), (unsigned)cipher);
        SSLDisposeContext(ctx);
        close(rawfd);
        return 1;
    }

    printf("Negotiated protocol: %s (enum=%d)\n", prot_string(negotiated), (int)negotiated);
    printf("Negotiated cipher:   0x%04X\n", (unsigned)cipher);
    printf("reads=%d  writes=%d\n", g_read_count, g_write_count);

    char req[256], buf[512];
    size_t written = 0, nread = 0;
    snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    SSLWrite(ctx, req, strlen(req), &written);
    SSLRead(ctx, buf, sizeof buf - 1, &nread);
    if (nread > 0) {
        buf[nread] = 0;
        char *crlf = strstr(buf, "\r\n");
        if (crlf) *crlf = 0;
        printf("HTTP response:       %s\n", buf);
    }

    SSLClose(ctx);
    SSLDisposeContext(ctx);
    close(rawfd);

    printf("\n");
    if (negotiated == kTLSProtocol12) {
        printf("SUCCESS: TLS 1.2 negotiated\n");
        return 0;
    }
    printf("FALLBACK: %s negotiated\n", prot_string(negotiated));
    return 1;
}
