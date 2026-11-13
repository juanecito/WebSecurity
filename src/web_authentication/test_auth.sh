#!/usr/bin/env bash
#
# test_auth.sh - Sets up a Python virtual environment, creates the
# certificates (if missing), starts auth_server.py and runs
# auth_client.py, which checks every authentication mechanism.
#
# Usage: ./test_auth.sh          Run the tests
#        ./test_auth.sh --clean  Delete the virtual environment, certificates and logs
#
# Optional variables: AUTH_PORT=5443

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
export AUTH_PORT="${AUTH_PORT:-5443}"

if [ "${1:-}" = "--clean" ]; then
    rm -rf .venv ca.key ca.pem ca.srl server.key server.csr server.pem \
           san.ext auth_server.log __pycache__
    echo "Generated files deleted."
    exit 0
fi

PID=""
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true; }
trap stop EXIT INT TERM

echo "== Python environment"
command -v python3 >/dev/null || { echo "python3 is missing"; exit 1; }
if [ ! -d .venv ]; then
    python3 -m venv .venv || { echo "Install python3-venv (sudo apt install python3-venv)"; exit 1; }
fi
.venv/bin/pip install -q --disable-pip-version-check \
    flask argon2-cffi pyjwt cryptography requests
echo "Dependencies installed in .venv"

echo "== Certificates"
if [ ! -f server.pem ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
        -days 365 -subj "/CN=My Test CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
        -subj "/CN=localhost" 2>/dev/null
    cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out server.pem -days 365 -extfile san.ext 2>/dev/null
    echo "CA and localhost certificate created"
else
    echo "Reusing the existing ones"
fi

# TOTP secret shared between server and client for the demo only.
TOTP_SECRET="$(.venv/bin/python -c 'from auth_utils import new_totp_secret; print(new_totp_secret())')"
export TOTP_SECRET

echo "== Starting the server on https://localhost:$AUTH_PORT"
.venv/bin/python auth_server.py > auth_server.log 2>&1 &
PID=$!
for _ in $(seq 50); do
    curl -s --noproxy localhost --cacert ca.pem "https://localhost:$AUTH_PORT/profile" >/dev/null 2>&1 && break
    kill -0 "$PID" 2>/dev/null || { echo "The server did not start:"; cat auth_server.log; exit 1; }
    sleep 0.2
done

echo
.venv/bin/python auth_client.py
