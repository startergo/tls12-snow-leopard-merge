/*
 * ssltest_multi.c — multi-connection TLS harness for Snow Leopard
 *                   libsecurity_ssl-55002 (patched TLS 1.2 build).
 *
 * Purpose: reproduce, OUTSIDE Safari, the sub-resource SSL failures that a real
 * browser hits (see docs/KNOWN-ISSUE-subresource-tls.md). The original ssltest.c
 * does a SINGLE full handshake and always succeeds; a browser does one full
 * handshake then MANY more connections to the same host, which are typically
 * RESUMED (abbreviated) handshakes and/or CONCURRENT. This harness exercises both.
 *
 * Modes:
 *   single                 one connection (baseline; like ssltest.c)
 *   resume                 two SEQUENTIAL connections sharing a peer ID; the 2nd
 *                          should resume the 1st's session (abbreviated handshake)
 *   concurrent <N>         N CONCURRENT connections (fork), each a full handshake
 *   serial <N>             N sequential connections sharing a peer ID (resume x N)
 *
 * Resumption is driven by SSLSetPeerID: contexts sharing the same peer ID will
 * try to resume a cached session. Stock ssltest.c never calls SSLSetPeerID, which
 * is exactly why it never exercised the resume path.
 *
 * Compile against patched dylib (direct link):
 *   gcc -std=c99 -o /tmp/ssltest_multi /tmp/ssltest_multi.c \
 *       /tmp/libsecurity_ssl_tls12.dylib \
 *       -framework CoreFoundation \
 *       -mmacosx-version-min=10.6 -arch x86_64
 *
 * Compile against stock Security (baseline comparison):
 *   gcc -std=c99 -o /tmp/ssltest_multi_stock /tmp/ssltest_multi.c \
 *       -framework Security -framework CoreFoundation \
 *       -mmacosx-version-min=10.6 -arch x86_64
 *
 * Usage:
 *   ssltest_multi <host> <port> <mode> [N] [-v]
 *   ssltest_multi www.gannett-cdn.com 443 resume -v
 *   ssltest_multi www.gannett-cdn.com 443 concurrent 8
 *   ssltest_multi apple.com 443 serial 5
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
#include <sys/wait.h>
#include <netdb.h>
#include <Security/SecureTransport.h>

#define kTLSProtocol11  ((SSLProtocol)7)
#define kTLSProtocol12  ((SSLProtocol)8)

#define CONNECT_TIMEOUT_SEC  10
#define OVERALL_TIMEOUT_SEC  60   /* generous; multiple connections */

/* ── per-connection I/O state ─────────────────────────────────────── */
typedef struct { int fd; int verbose; int rcount; int wcount; } Conn;

static OSStatus ssl_read(SSLConnectionRef conn, void *data, size_t *len)
{
    Conn *c = (Conn *)(intptr_t)conn;
    ssize_t n = read(c->fd, data, *len);
    if (n > 0) {
        if (c->verbose) fprintf(stderr, "    [io] read  #%d: %zd bytes\n", ++c->rcount, n);
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
        if (c->verbose) fprintf(stderr, "    [io] write #%d: %zd bytes\n", ++c->wcount, n);
        *len = (size_t)n; return noErr;
    }
    *len = 0;
    return (errno == EAGAIN) ? errSSLWouldBlock : errSSLClosedAbort;
}

static void alarm_handler(int sig) {
    (void)sig;
    fprintf(stderr, "TIMEOUT after %d seconds\n", OVERALL_TIMEOUT_SEC);
    _exit(2);
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
        case 0:     return "noErr";
        case -9800: return "errSSLProtocol";
        case -9801: return "errSSLNegotiation";
        case -9802: return "errSSLFatalAlert";
        case -9803: return "errSSLWouldBlock";
        case -9804: return "errSSLSessionNotFound";
        case -9805: return "errSSLClosedGraceful";
        case -9806: return "errSSLClosedAbort";
        case -9807: return "errSSLXCertChainInvalid";
        case -9808: return "errSSLBadCert";
        case -9809: return "errSSLCrypto";
        case -9810: return "errSSLInternal";
        case -9811: return "errSSLModuleAttach";
        case -9812: return "errSSLUnknownRootCert";
        case -9813: return "errSSLNoRootCert";
        case -9814: return "errSSLCertExpired";
        case -9815: return "errSSLCertNotYetValid";
        case -9816: return "errSSLClosedNoNotify";
        case -9817: return "errSSLBufferOverflow";
        case -9818: return "errSSLBadCipherSuite";
        case -9819: return "errSSLPeerUnexpectedMsg";
        case -9820: return "errSSLPeerBadRecordMac";
        case -9821: return "errSSLPeerDecryptionFail";
        case -9822: return "errSSLPeerRecordOverflow";
        case -9823: return "errSSLPeerDecompressFail";
        case -9824: return "errSSLPeerHandshakeFail";
        case -9825: return "errSSLPeerBadCert";
        case -9826: return "errSSLPeerUnsupportedCert";
        case -9827: return "errSSLPeerCertRevoked";
        case -9828: return "errSSLPeerCertExpired";
        case -9829: return "errSSLPeerCertUnknown";
        case -9830: return "errSSLIllegalParam";
        case -9831: return "errSSLPeerUnknownCA";
        case -9832: return "errSSLPeerAccessDenied";
        case -9833: return "errSSLPeerDecodeError";
        case -9834: return "errSSLPeerDecryptError";
        case -9835: return "errSSLPeerExportRestriction";
        case -9836: return "errSSLPeerProtocolVersion";
        case -9837: return "errSSLPeerInsufficientSecurity";
        case -9838: return "errSSLPeerInternalError";
        case -9839: return "errSSLPeerUserCancelled";
        case -9840: return "errSSLPeerNoRenegotiation";
        case -9841: return "errSSLPeerAuthCompleted";
        case -9842: return "errSSLClientCertRequested";
        case -9843: return "errSSLHostNameMismatch";
        case -9844: return "errSSLConnectionRefused";
        case -9845: return "errSSLDecryptionFail";
        case -9846: return "errSSLBadRecordMac";
        case -9847: return "errSSLRecordOverflow";
        case -9848: return "errSSLBadConfiguration";
        case -9849: return "errSSLUnexpectedRecord";
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

/* Perform one TLS connection + handshake + tiny GET. Returns 0 on success.
 * peerID/peerIDLen: if non-NULL, SSLSetPeerID is called so the session is cached
 * and (on later connections with the same ID) resumption is attempted.
 * label: prefix for log lines (e.g. "conn#2"). */
static int do_one(const char *host, const char *port,
                  const void *peerID, size_t peerIDLen,
                  const char *label, int verbose)
{
    int rawfd = tcp_connect(host, port);
    if (rawfd < 0) { fprintf(stderr, "[%s] TCP connect failed\n", label); return 1; }

    Conn conn = { rawfd, verbose, 0, 0 };
    SSLContextRef ctx;
    OSStatus err = SSLNewContext(false, &ctx);
    if (err) { fprintf(stderr, "[%s] SSLNewContext: %d\n", label, (int)err); close(rawfd); return 1; }

    SSLSetIOFuncs(ctx, ssl_read, ssl_write);
    SSLSetConnection(ctx, (SSLConnectionRef)&conn);
    SSLSetPeerDomainName(ctx, host, strlen(host));
    SSLSetEnableCertVerify(ctx, false);

    /* Force TLS 1.2 ceiling (same as ssltest.c default path). */
    SSLSetProtocolVersionEnabled(ctx, kSSLProtocolAll, false);
    SSLSetProtocolVersionEnabled(ctx, kSSLProtocol3, true);
    SSLSetProtocolVersionEnabled(ctx, kTLSProtocol1, true);
    SSLSetProtocolVersionEnabled(ctx, kTLSProtocol11, true);
    SSLSetProtocolVersionEnabled(ctx, kTLSProtocol12, true);

    /* The resumption trigger: a shared peer ID. Without this, no session is
     * cached and every handshake is full. With it, the 2nd+ connection that
     * shares the ID attempts an abbreviated (resumed) handshake. */
    if (peerID && peerIDLen) {
        OSStatus pe = SSLSetPeerID(ctx, peerID, peerIDLen);
        if (pe != noErr)
            fprintf(stderr, "[%s] SSLSetPeerID: %d (%s)\n", label, (int)pe, ssl_errstr(pe));
    }

    do { err = SSLHandshake(ctx); } while (err == errSSLWouldBlock);

    SSLProtocol negotiated = kSSLProtocolUnknown;
    SSLGetNegotiatedProtocolVersion(ctx, &negotiated);
    SSLCipherSuite cipher = 0;
    SSLGetNegotiatedCipher(ctx, &cipher);

    /* Did this handshake RESUME a prior session? (abbreviated handshake) */
    Boolean resumed = false;
    {
        /* SSLGetResumableSessionInfo: available on 10.6. sessionID/len optional. */
        char sid[64]; size_t sidLen = sizeof sid;
        OSStatus re = SSLGetResumableSessionInfo(ctx, &resumed, sid, &sidLen);
        (void)re; /* if unavailable, resumed stays false */
    }

    if (err != noErr) {
        fprintf(stderr, "[%s] HANDSHAKE FAILED: %d (%s)  proto=%s cipher=0x%04X "
                        "resumed=%s reads=%d writes=%d\n",
                label, (int)err, ssl_errstr(err),
                prot_string(negotiated), (unsigned)cipher,
                resumed ? "YES" : "no", conn.rcount, conn.wcount);
        SSLDisposeContext(ctx);
        close(rawfd);
        return 1;
    }

    /* tiny GET so we actually exchange app data on the (possibly resumed) session */
    char req[256], buf[256];
    size_t written = 0, nread = 0;
    snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host);
    OSStatus we = SSLWrite(ctx, req, strlen(req), &written);
    OSStatus rde = SSLRead(ctx, buf, sizeof buf - 1, &nread);
    int appOK = (we == noErr && nread > 0);

    fprintf(stderr, "[%s] OK: proto=%s cipher=0x%04X resumed=%s "
                    "appdata=%s (w=%d r=%zu) reads=%d writes=%d\n",
            label, prot_string(negotiated), (unsigned)cipher,
            resumed ? "YES" : "no",
            appOK ? "ok" : "FAIL", (int)we, nread, conn.rcount, conn.wcount);
    if (we != noErr || rde != noErr)
        fprintf(stderr, "[%s]   SSLWrite=%s SSLRead=%s\n",
                label, ssl_errstr(we), ssl_errstr(rde));

    SSLClose(ctx);
    SSLDisposeContext(ctx);
    close(rawfd);
    return appOK ? 0 : 1;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr,
          "usage: %s <host> <port> <mode> [N] [-v]\n"
          "  modes: single | resume | serial <N> | concurrent <N>\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    const char *port = argv[2];
    const char *mode = argv[3];
    int N = 4, verbose = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else N = atoi(argv[i]);
    }
    if (N < 1) N = 1;

    signal(SIGALRM, alarm_handler);
    alarm(OVERALL_TIMEOUT_SEC);

    /* peer ID = the hostname; shared across connections to enable resumption. */
    const void *pid = host;
    size_t pidLen = strlen(host);

    int rc = 0;

    if (strcmp(mode, "single") == 0) {
        printf("=== single full handshake to %s:%s ===\n", host, port);
        rc = do_one(host, port, NULL, 0, "single", verbose);
    }
    else if (strcmp(mode, "resume") == 0) {
        printf("=== resume test: 2 sequential connections sharing peer ID ===\n");
        printf("--- connection 1 (full handshake, caches session) ---\n");
        int r1 = do_one(host, port, pid, pidLen, "conn#1", verbose);
        printf("--- connection 2 (should RESUME) ---\n");
        int r2 = do_one(host, port, pid, pidLen, "conn#2", verbose);
        printf("\nRESULT: conn#1=%s conn#2=%s\n",
               r1 ? "FAIL" : "ok", r2 ? "FAIL" : "ok");
        printf("If conn#1 succeeds and conn#2 fails -> the RESUMED handshake is the bug.\n");
        rc = (r1 || r2);
    }
    else if (strcmp(mode, "serial") == 0) {
        printf("=== serial test: %d sequential connections sharing peer ID ===\n", N);
        for (int i = 0; i < N; i++) {
            char lbl[32]; snprintf(lbl, sizeof lbl, "serial#%d", i + 1);
            int r = do_one(host, port, pid, pidLen, lbl, verbose);
            if (r) { rc = 1; printf(">>> first failure at connection %d (see above)\n", i + 1); }
        }
    }
    else if (strcmp(mode, "concurrent") == 0) {
        printf("=== concurrent test: %d parallel full handshakes (fork) ===\n", N);
        pid_t pids[256];
        if (N > 256) N = 256;
        for (int i = 0; i < N; i++) {
            pid_t p = fork();
            if (p == 0) {
                char lbl[32]; snprintf(lbl, sizeof lbl, "par#%d", i + 1);
                /* shared peer ID so concurrent conns also race the session cache */
                int r = do_one(host, port, pid, pidLen, lbl, verbose);
                _exit(r ? 1 : 0);
            }
            pids[i] = p;
        }
        int fails = 0;
        for (int i = 0; i < N; i++) {
            int st = 0; waitpid(pids[i], &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) fails++;
        }
        printf("\nRESULT: %d/%d concurrent connections failed\n", fails, N);
        printf("If some fail under concurrency but `single` always works -> concurrent/shared-state bug.\n");
        rc = (fails > 0);
    }
    else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 1;
    }

    alarm(0);
    return rc;
}
