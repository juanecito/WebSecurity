#!/usr/bin/env bash
#
# wireshark_tls.sh - Captures the traffic of server.c/client.c on the loopback
# interface and shows the SSL/TLS packets with Wireshark (tshark or the GUI).
#
# Usage:
#   ./wireshark_tls.sh                 Capture while test_tls.sh runs, then show the TLS packets
#   ./wireshark_tls.sh --ssl3          Same, passing --ssl3 to test_tls.sh
#   ./wireshark_tls.sh --live          Capture until Ctrl+C (run server/client yourself meanwhile)
#   ./wireshark_tls.sh --read FILE     Only show the TLS packets of an existing capture
#   ./wireshark_tls.sh --gui [...]     Open the result in the Wireshark GUI instead of the terminal
#                                      (--gui --live opens a live capture in Wireshark)
#
# Optional variables:
#   PORT=4433                          Port used by server.c (decoded as TLS)
#   IFACE=lo                           Capture interface
#   SSLKEYLOGFILE=/path/keys.log       NSS key log file to decrypt the records (see notes below)
#   TSHARK, DUMPCAP, WIRESHARK         Paths to the Wireshark binaries
#
# Notes:
#   - Capturing needs permission to run dumpcap: be in the "wireshark" group
#     (sudo dpkg-reconfigure wireshark-common; sudo usermod -aG wireshark "$USER"
#     and log in again). Otherwise the script falls back to "sudo dumpcap".
#   - The terminal view needs tshark (sudo apt install tshark). Without it the
#     capture is opened in the Wireshark GUI.
#   - Wireshark dissects SSL 3.0 and TLS with the same "tls" dissector, so the
#     display filter "tls" shows SSLv3, TLSv1.2 and TLSv1.3 records.
#   - Without the session keys only the handshake is readable: in TLS 1.3
#     everything after the ServerHello appears as "Application Data". Give a key
#     log with SSLKEYLOGFILE (the programs must write it, e.g. with
#     SSL_CTX_set_keylog_callback) to see the decrypted messages.

set -euo pipefail
export LC_NUMERIC=C   # "0.000251" and not "0,000251" in printf

PORT="${PORT:-4433}"
IFACE="${IFACE:-lo}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
TSHARK="${TSHARK:-$(command -v tshark || true)}"
DUMPCAP="${DUMPCAP:-$(command -v dumpcap || echo /usr/bin/dumpcap)}"
WIRESHARK="${WIRESHARK:-$(command -v wireshark || true)}"

cd "$DIR"

# --- Helpers ----------------------------------------------------------------

GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; YELLOW=$'\e[33m'; NORMAL=$'\e[0m'
[ -t 1 ] || { GREEN=""; RED=""; BLUE=""; YELLOW=""; NORMAL=""; }

title() { echo; echo "${BLUE}== $*${NORMAL}"; }
ok()    { echo "${GREEN}[OK]${NORMAL} $*"; }
warn()  { echo "${YELLOW}[WARN]${NORMAL} $*"; }
fail()  { echo "${RED}[FAIL]${NORMAL} $*"; }

usage() {
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# Wireshark only decodes TLS automatically on well-known ports (443, 853...),
# so port $PORT is decoded as TLS explicitly.
ws_options() {
    WS_OPTS=(-d "tcp.port==$PORT,tls")
    if [ -n "${SSLKEYLOGFILE:-}" ] && [ -f "$SSLKEYLOGFILE" ]; then
        WS_OPTS+=(-o "tls.keylog_file:$SSLKEYLOGFILE")
        ok "decrypting with the key log $SSLKEYLOGFILE"
    fi
}

# --- Capture ----------------------------------------------------------------

CAPTURE_PID=""
CAPTURE_SUDO=0
PIDFILE=""

choose_dumpcap() {
    # -L opens the interface, so it fails without capture permissions.
    if [ -x "$DUMPCAP" ] && "$DUMPCAP" -L -i "$IFACE" >/dev/null 2>&1; then
        CAPTURE_SUDO=0
        ok "dumpcap can capture on $IFACE"
    elif command -v sudo >/dev/null; then
        warn "no permission to capture with dumpcap; using sudo"
        warn "(to avoid it: sudo usermod -aG wireshark \"\$USER\" and log in again)"
        sudo -v
        CAPTURE_SUDO=1
    else
        fail "cannot run $DUMPCAP and sudo is not available"; exit 1
    fi
}

# start_capture <file.pcapng>
start_capture() {
    local out="$1" err="$LOGS/dumpcap.log"
    rm -f "$out"
    if [ "$CAPTURE_SUDO" -eq 1 ]; then
        PIDFILE="$(mktemp)"
        sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$PIDFILE" \
            "$DUMPCAP" -q -i "$IFACE" -f "tcp port $PORT" -w "$out" 2>"$err" &
    else
        "$DUMPCAP" -q -i "$IFACE" -f "tcp port $PORT" -w "$out" 2>"$err" &
    fi
    CAPTURE_PID=$!

    # Wait until dumpcap has created the file (5 s at most).
    local i
    for i in $(seq 50); do
        [ -s "$out" ] && break
        kill -0 "$CAPTURE_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [ ! -s "$out" ]; then
        fail "dumpcap did not start"; sed 's/^/    /' "$err"; exit 1
    fi
    ok "capturing tcp port $PORT on $IFACE into $out"
}

stop_capture() {
    [ -n "$CAPTURE_PID" ] || return 0
    sleep 0.5   # let the last packets reach the file
    if [ "$CAPTURE_SUDO" -eq 1 ]; then
        sudo kill -INT "$(cat "$PIDFILE")" 2>/dev/null || true
    else
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
    fi
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
    if [ "$CAPTURE_SUDO" -eq 1 ]; then
        sudo chown "$(id -u):$(id -g)" "$CAPTURE" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
}
trap stop_capture EXIT

# --- Display ----------------------------------------------------------------

# tshark_fields <file> <display filter> <field>...
tshark_fields() {
    local file="$1" filter="$2"; shift 2
    local args=() f
    for f in "$@"; do args+=(-e "$f"); done
    "$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "$filter" -T fields \
        -E separator='|' -E occurrence=a -E aggregator=',' "${args[@]}" 2>/dev/null
}

show_terminal() {
    local file="$1"

    title "SSL/TLS packets (display filter: tls)"
    printf '%-6s %-7s %-10s %-23s %-23s %-9s %s\n' \
        "Frame" "Stream" "Time" "Source" "Destination" "Protocol" "Info"
    tshark_fields "$file" "tls" frame.number tcp.stream frame.time_relative \
        ip.src tcp.srcport ip.dst tcp.dstport _ws.col.protocol _ws.col.info |
    while IFS='|' read -r num stream t src sport dst dport proto info; do
        printf '%-6s %-7s %-10.6f %-23s %-23s %-9s %s\n' \
            "$num" "$stream" "$t" "$src:$sport" "$dst:$dport" "$proto" "$info"
    done

    title "Handshake per connection"
    # Custom columns (%Cus) print names ("TLS 1.3", "TLS_AES_256_GCM_SHA384")
    # instead of the raw codes that -T fields gives.
    local cols='"Stream","%Cus:tcp.stream"'
    cols+=',"Type","%Cus:tls.handshake.type"'
    cols+=',"Version","%Cus:tls.handshake.version"'
    cols+=',"Supported","%Cus:tls.handshake.extensions.supported_version"'
    cols+=',"Suites","%Cus:tls.handshake.ciphersuite"'
    cols+=',"SNI","%Cus:tls.handshake.extensions_server_name"'
    cols+=',"Level","%Cus:tls.alert_message.level"'
    cols+=',"Alert","%Cus:tls.alert_message.desc"'

    local rows
    rows="$("$TSHARK" -r "$file" "${WS_OPTS[@]}" -T tabs -o "gui.column.format:$cols" \
        -Y "tls.handshake.type==1 || tls.handshake.type==2 || tls.alert_message.desc" \
        2>/dev/null | tr '\t' '|')"
    if [ -z "$rows" ]; then
        warn "no ClientHello, ServerHello or alerts in $file"; return
    fi

    local last="" stream type ver supported suites sni level alert n
    while IFS='|' read -r stream type ver supported suites sni level alert; do
        if [ "$stream" != "$last" ]; then
            echo "${BLUE}-- TCP connection (stream $stream)${NORMAL}"
            last="$stream"
        fi
        case "$type" in
            "Client Hello"*)
                # In TLS 1.3 legacy_version stays at TLS 1.2 and the versions the
                # client really accepts travel in the supported_versions extension.
                n=$(( $(tr -cd ',' <<<"$suites" | wc -c) + 1 ))
                echo "  ClientHello  legacy_version=$ver supported_versions=[${supported:--}]"
                echo "               SNI=${sni:--}, offers $n cipher suites"
                ;;
            "Server Hello"*)
                echo "  ServerHello  ${GREEN}version=${supported:-$ver}${NORMAL}" \
                     "cipher_suite=$suites"
                [ "$type" = "Server Hello" ] || echo "               same record: $type"
                ;;
            *)
                echo "  ${RED}Alert${NORMAL}        level=$level description=$alert"
                ;;
        esac
    done <<<"$rows"
}

show_gui() {
    local file="$1"
    [ -n "$WIRESHARK" ] || { fail "wireshark not found"; exit 1; }
    ok "opening $file in Wireshark with the filter \"tls\""
    "$WIRESHARK" -r "$file" "${WS_OPTS[@]}" -Y "tls" >/dev/null 2>&1 &
}

show() {
    local file="$1"
    ws_options
    if [ "$USE_GUI" -eq 0 ] && [ -n "$TSHARK" ]; then
        show_terminal "$file"
    elif [ -n "$WIRESHARK" ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        [ "$USE_GUI" -eq 1 ] || warn "tshark not found (sudo apt install tshark); using the GUI"
        show_gui "$file"
    else
        fail "neither tshark nor a graphical Wireshark is available"
        echo "Install tshark (sudo apt install tshark) and run: $0 --read $file"
        exit 1
    fi
}

# --- Main -------------------------------------------------------------------

USE_GUI=0
MODE="test"
TEST_ARGS=()
READ_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gui)  USE_GUI=1 ;;
        --ssl3) TEST_ARGS+=(--ssl3) ;;
        --live) MODE="live" ;;
        --read) MODE="read"; READ_FILE="${2:-}"; [ -n "$READ_FILE" ] || usage; shift ;;
        -h|--help|*) usage ;;
    esac
    shift
done

mkdir -p "$LOGS"
#CAPTURE="$LOGS/tls_capture.pcapng"
CAPTURE="/tmp/tls_capture.pcapng"

case "$MODE" in
    read)
        [ -f "$READ_FILE" ] || { fail "cannot find $READ_FILE"; exit 1; }
        show "$READ_FILE"
        ;;

    live)
        if [ "$USE_GUI" -eq 1 ]; then
            # Wireshark captures by itself (it also runs dumpcap).
            ws_options
            ok "live capture in Wireshark: tcp port $PORT on $IFACE, filter \"tls\""
            "$WIRESHARK" -i "$IFACE" -k -f "tcp port $PORT" "${WS_OPTS[@]}" -Y "tls" \
                >/dev/null 2>&1 &
            exit 0
        fi
        title "Live capture"
        choose_dumpcap
        start_capture "$CAPTURE"
        echo "Run server and client in another terminal, for example:"
        echo "  build/server $PORT tls1.3 build/server.pem build/server.key"
        echo "  build/client localhost $PORT tls1.3 build/ca.pem \"Hello\""
        echo "Press Ctrl+C to stop the capture."
        trap 'echo' INT
        wait "$CAPTURE_PID" 2>/dev/null || true
        trap - INT
        stop_capture
        show "$CAPTURE"
        ;;

    test)
        [ -x "$DIR/test_tls.sh" ] || { fail "cannot find test_tls.sh in $DIR"; exit 1; }
        title "Capture"
        choose_dumpcap
        start_capture "$CAPTURE"
        title "Running test_tls.sh ${TEST_ARGS[*]:-} to generate traffic"
        rc=0
        PORT="$PORT" "$DIR/test_tls.sh" "${TEST_ARGS[@]}" || rc=$?
        stop_capture
        [ "$rc" -eq 0 ] || warn "test_tls.sh finished with code $rc"
        ok "capture saved in $CAPTURE"
        show "$CAPTURE"
        ;;
esac
