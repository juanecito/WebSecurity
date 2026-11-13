#!/usr/bin/env bash
#
# test_tls.sh - Creates the certificates, builds server.c and client.c and
# tests the connection with TLS 1.3, TLS 1.2 and, optionally, SSL 3.0.
#
# Usage:
#   ./test_tls.sh           Test TLS 1.3, TLS 1.2 and mismatched versions
#   ./test_tls.sh --ssl3    Also build an OpenSSL with SSL 3.0 and test it
#   ./test_tls.sh --clean   Delete generated certificates, binaries and logs
#
# Optional variables:
#   PORT=4433                      Server port
#   OSSL_SSL3=$DIR/ossl-ssl3      Where to install/find the OpenSSL with SSL 3.0
#   OSSL_VERSION=openssl-3.0.13    OpenSSL tag built for SSL 3.0

set -euo pipefail

PORT="${PORT:-4433}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
BUILD_DIR="$DIR/build"
OSSL_SSL3="${OSSL_SSL3:-$BUILD_DIR/ossl-ssl3}"
OSSL_VERSION="${OSSL_VERSION:-openssl-3.0.13}"

cd "$DIR"

# --- Helpers ----------------------------------------------------------------

GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; NORMAL=$'\e[0m'
[ -t 1 ] || { GREEN=""; RED=""; BLUE=""; NORMAL=""; }

title() { echo; echo "${BLUE}== $*${NORMAL}"; }
ok()    { echo "${GREEN}[OK]${NORMAL} $*"; }
fail()  { echo "${RED}[FAIL]${NORMAL} $*"; }

SERVER_PID=""
stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
}
trap stop_server EXIT INT TERM

clean() {
    rm -rf "$BUILD_DIR"
    rm -rf "$LOGS"
    echo "Generated files deleted."
}

# --- 1. Dependencies --------------------------------------------------------

check_dependencies() {
    title "Checking dependencies"
    local missing=0
    for cmd in gcc openssl; do
        if command -v "$cmd" >/dev/null; then
            ok "$cmd found"
        else
            fail "$cmd missing"; missing=1
        fi
    done
    if echo '#include <openssl/ssl.h>' | gcc -E - >/dev/null 2>&1; then
        ok "OpenSSL headers found"
    else
        fail "OpenSSL headers missing (sudo apt install libssl-dev)"; missing=1
    fi
    for f in server.c client.c; do
        [ -f "$f" ] || { fail "cannot find $f in $DIR"; missing=1; }
    done
    [ "$missing" -eq 0 ] || exit 1
    echo "System OpenSSL: $(openssl version)"
}

# --- 2. Certificates --------------------------------------------------------

create_certificates() {
    title "Certificates"
    if [ -f $BUILD_DIR/ca.pem ] && [ -f $BUILD_DIR/server.pem ] && [ -f $BUILD_DIR/server.key ]; then
        ok "already present, reusing them (use --clean to regenerate)"
        return
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -keyout $BUILD_DIR/ca.key -out $BUILD_DIR/ca.pem \
        -days 365 -subj "/CN=My Test CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    ok "test CA created ($BUILD_DIR/ca.pem)"

    openssl req -newkey rsa:2048 -nodes -keyout $BUILD_DIR/server.key -out $BUILD_DIR/server.csr \
        -subj "/CN=localhost" 2>/dev/null
    cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
    openssl x509 -req -in $BUILD_DIR/server.csr -CA $BUILD_DIR/ca.pem -CAkey $BUILD_DIR/ca.key -CAcreateserial \
        -out $BUILD_DIR/server.pem -days 365 -extfile san.ext 2>/dev/null
    ok "server certificate for localhost ($BUILD_DIR/server.pem)"

    openssl verify -CAfile $BUILD_DIR/ca.pem $BUILD_DIR/server.pem >/dev/null && ok "the chain verifies"
}

# --- 3. Build ---------------------------------------------------------------

build() {
    title "Building against the system OpenSSL"
    gcc -Wall -Wextra -o $BUILD_DIR/server server.c -lssl -lcrypto
    gcc -Wall -Wextra -o $BUILD_DIR/client client.c -lssl -lcrypto
    ok "server and client built"
}

build_openssl_ssl3() {
    title "OpenSSL with SSL 3.0 in $OSSL_SSL3"
    if [ -f "$OSSL_SSL3/lib/libssl.so" ]; then
        ok "already built, reusing it"
    else
        local src
        src="$(mktemp -d)"
        echo "Downloading $OSSL_VERSION and building (takes a few minutes)..."
        git clone -q --depth 1 --branch "$OSSL_VERSION" \
            https://github.com/openssl/openssl.git "$src/openssl" 2>/dev/null
        (
            cd "$src/openssl"
            ./Configure enable-ssl3 enable-ssl3-method no-tests \
                --prefix="$OSSL_SSL3" --libdir=lib >/dev/null
            make -j"$(nproc)" >/dev/null 2>&1
            make install_sw >/dev/null 2>&1
        )
        rm -rf "$src"
        ok "OpenSSL installed in $OSSL_SSL3"
    fi

    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o $BUILD_DIR/server3 server.c \
        -L"$OSSL_SSL3/lib" -Wl,-rpath,"$OSSL_SSL3/lib" -lssl -lcrypto
    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o $BUILD_DIR/client3 client.c \
        -L"$OSSL_SSL3/lib" -Wl,-rpath,"$OSSL_SSL3/lib" -lssl -lcrypto
    ok "server3 and client3 built against that OpenSSL"
}

# --- 4. Tests ---------------------------------------------------------------

FAILURES=0

# run_test <name> <server_bin> <server_proto> <client_bin> <client_proto> <yes|no|info>
#   yes: must connect · no: the handshake must fail · info: report only
run_test() {
    local name="$1" srv="$2" psrv="$3" cli="$4" pcli="$5" expected="$6"
    local srv_log="$LOGS/$name.server.log" cli_log="$LOGS/$name.client.log"

    title "Test: $name server $psrv, client $pcli)"

    "$srv" "$PORT" "$psrv" $BUILD_DIR/server.pem $BUILD_DIR/server.key >"$srv_log" 2>&1 &
    SERVER_PID=$!

    # Wait until the server is listening (5 s at most).
    local i
    for i in $(seq 50); do
        grep -q "Listening" "$srv_log" 2>/dev/null && break
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    if ! grep -q "Listening" "$srv_log"; then
        fail "the server did not start"; sed 's/^/    /' "$srv_log"
        FAILURES=$((FAILURES + 1)); stop_server; return
    fi

    local rc=0
    timeout 10 "$cli" localhost "$PORT" "$pcli" $BUILD_DIR/ca.pem "Hello from $pcli" \
        >"$cli_log" 2>&1 || rc=$?
    sleep 0.2
    stop_server

    echo "  Client:"; sed 's/^/    /' "$cli_log"
    echo "  Server:"; sed 's/^/    /' "$srv_log"

    if [ "$expected" = "yes" ] && [ "$rc" -eq 0 ] && grep -q "^Reply:" "$cli_log"; then
        ok "connection and echo correct"
    elif [ "$expected" = "no" ] && [ "$rc" -ne 0 ]; then
        ok "the handshake fails, as expected"
    elif [ "$expected" = "info" ]; then
        if [ "$rc" -eq 0 ]; then
            ok "this OpenSSL does support $pcli"
        else
            ok "this OpenSSL does not support $pcli (normal for distributions)"
        fi
    else
        fail "unexpected result (client exit code: $rc)"
        FAILURES=$((FAILURES + 1))
    fi
}

# --- Main -------------------------------------------------------------------

WITH_SSL3=0
case "${1:-}" in
    --clean) clean; exit 0 ;;
    --ssl3)  WITH_SSL3=1 ;;
    "")      ;;
    *)       echo "Usage: $0 [--ssl3 | --clean]"; exit 1 ;;
esac

mkdir -p "$BUILD_DIR"
check_dependencies
create_certificates
build
mkdir -p "$LOGS"

run_test tls1.3      $BUILD_DIR/server tls1.3 $BUILD_DIR/client tls1.3 yes
run_test tls1.2      $BUILD_DIR/server tls1.2 $BUILD_DIR/client tls1.2 yes
run_test mismatch    $BUILD_DIR/server tls1.3 $BUILD_DIR/client tls1.2 no
run_test ssl3-system $BUILD_DIR/server ssl3   $BUILD_DIR/client ssl3   info

if [ "$WITH_SSL3" -eq 1 ]; then
    command -v git >/dev/null || { fail "--ssl3 needs git"; exit 1; }
    build_openssl_ssl3
    run_test ssl3 $BUILD_DIR/server3 ssl3 $BUILD_DIR/client3 ssl3 yes
fi

title "Summary"
if [ "$FAILURES" -eq 0 ]; then
    ok "all tests behaved as expected (logs in $LOGS)"
else
    fail "$FAILURES test(s) with unexpected results (logs in $LOGS)"
    exit 1
fi
