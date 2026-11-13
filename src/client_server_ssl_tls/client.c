/*
 * client.c - Client for SSL 3.0, TLS 1.2 or TLS 1.3 with OpenSSL.
 *
 * Build:  gcc -Wall -o client client.c -lssl -lcrypto
 * Usage:  ./client <host> <port> <ssl3|tls1.2|tls1.3> <ca.pem> [message]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

static int protocol_version(const char *name)
{
    if (strcmp(name, "ssl3") == 0)   return SSL3_VERSION;
    if (strcmp(name, "tls1.2") == 0) return TLS1_2_VERSION;
    if (strcmp(name, "tls1.3") == 0) return TLS1_3_VERSION;
    return -1;
}

static void die(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static SSL_CTX *create_context(int version, const char *ca)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        die("could not create the SSL context");

    if (!SSL_CTX_set_min_proto_version(ctx, version) ||
        !SSL_CTX_set_max_proto_version(ctx, version))
        die("protocol version not supported by this OpenSSL");

    if (version == SSL3_VERSION) {
        SSL_CTX_set_security_level(ctx, 0);
        if (!SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"))
            die("no ciphers available for SSL 3.0");
    }

    /* Verify the server certificate against our CA. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0)
        die("could not load the CA certificate");

    return ctx;
}

static int connect_to(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res, *p;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        exit(EXIT_FAILURE);
    }

    int s = -1;
    for (p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0)
            continue;
        if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);

    if (s < 0) {
        fprintf(stderr, "Could not connect to %s:%s\n", host, port);
        exit(EXIT_FAILURE);
    }
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6) {
        fprintf(stderr, "Usage: %s <host> <port> <ssl3|tls1.2|tls1.3> <ca.pem> [message]\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    else
    {
        fprintf(stdout, "==================================================================== \n"
                        "Parameters: %s \n"
                        "host=%s \n"
                        "port=%s \n"
                        "version(ssl3|tls1.2|tls1.3)=%s \n"
                        "file_ca.pem=%s \n"
                        "message=%s \n"
                        "==================================================================== \n",
                argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
    }
    const char *host = argv[1];
    const char *message = argc == 6 ? argv[5] : "Hello, server";

    int version = protocol_version(argv[3]);
    if (version < 0) {
        fprintf(stderr, "Unknown protocol: %s\n", argv[3]);
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = create_context(version, argv[4]);
    int s = connect_to(host, argv[2]);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);
    SSL_set_tlsext_host_name(ssl, host);   /* SNI */
    SSL_set1_host(ssl, host);              /* The certificate must be for this host */

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Handshake failed (verification: %s)\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    printf("Connected with %s, cipher %s\n", SSL_get_version(ssl),
           SSL_get_cipher_name(ssl));

    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (cert) {
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        printf("Server certificate: %s\n", subject);
        X509_free(cert);
    }

    SSL_write(ssl, message, strlen(message));

    char buf[1200];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Reply: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(s);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
