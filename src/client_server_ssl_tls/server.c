/*
 * server.c - Echo server over SSL 3.0, TLS 1.2 or TLS 1.3 with OpenSSL.
 *
 * Build:  gcc -Wall -o server server.c -lssl -lcrypto
 * Usage:  ./server <port> <ssl3|tls1.2|tls1.3> <cert.pem> <key.pem>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Map the protocol name to the OpenSSL constant. */
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

static SSL_CTX *create_context(int version, const char *cert, const char *key)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        die("could not create the SSL context");

    /* Set minimum and maximum to the same version: only that one is accepted. */
    if (!SSL_CTX_set_min_proto_version(ctx, version) ||
        !SSL_CTX_set_max_proto_version(ctx, version))
        die("protocol version not supported by this OpenSSL");

    if (version == SSL3_VERSION) {
        /* SSL 3.0 is insecure: OpenSSL blocks it unless the security level
         * is 0 and the library was built with enable-ssl3. */
        SSL_CTX_set_security_level(ctx, 0);
        if (!SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"))
            die("no ciphers available for SSL 3.0");
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0)
        die("could not load the certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
        die("could not load the private key");
    if (!SSL_CTX_check_private_key(ctx))
        die("the private key does not match the certificate");

    return ctx;
}

static int create_socket(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

static void handle_client(SSL_CTX *ctx, int client)
{
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    /* Handshake: version, cipher and keys are negotiated here. */
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }

    printf("Connection: %s, cipher %s\n", SSL_get_version(ssl),
           SSL_get_cipher_name(ssl));

    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Received: %s\n", buf);

        char reply[1100];
        int len = snprintf(reply, sizeof(reply), "Echo (%s): %s",
                           SSL_get_version(ssl), buf);
        SSL_write(ssl, reply, len);
    }

    SSL_shutdown(ssl);   /* Sends the close_notify alert. */
    SSL_free(ssl);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <port> <ssl3|tls1.2|tls1.3> <cert.pem> <key.pem>\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    else
    {
        fprintf(stdout, "==================================================================== \n"
                        "Parameters: %s \n"
                        "port=%s \n"
                        "version(ssl3|tls1.2|tls1.3)=%s \n"
                        "file_ca.pem=%s \n"
                        "file_key.pem=%s \n"
                        "==================================================================== \n",
                argv[0], argv[1], argv[2], argv[3], argv[4]);
    }

    int version = protocol_version(argv[2]);
    if (version < 0) {
        fprintf(stderr, "Unknown protocol: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    setvbuf(stdout, NULL, _IONBF, 0);   /* Show messages immediately */

    SSL_CTX *ctx = create_context(version, argv[3], argv[4]);
    int s = create_socket(atoi(argv[1]));
    printf("Listening on port %s with %s\n", argv[1], argv[2]);

    for (;;) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client = accept(s, (struct sockaddr *)&addr, &len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        handle_client(ctx, client);
        close(client);
    }

    close(s);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
