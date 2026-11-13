#!/usr/bin/env bash
#
# wireshark_auth.sh - Captures the HTTPS traffic of auth_server.py/auth_client.py
# on the loopback interface, decrypts it and analyses the authentication with
# Wireshark (tshark or the GUI): passwords, TOTP codes, cookies, CSRF and JWTs.
#
# Usage:
#   ./wireshark_auth.sh                Capture while test_auth.sh runs, then analyse it
#   ./wireshark_auth.sh --no-keys      Same, without the TLS key log (what an eavesdropper sees)
#   ./wireshark_auth.sh --live         Capture until Ctrl+C (run server/client yourself meanwhile)
#   ./wireshark_auth.sh --read FILE    Only analyse an existing capture
#   ./wireshark_auth.sh --gui [...]    Open the result in the Wireshark GUI instead of the terminal
#                                      (--gui --live opens a live capture in Wireshark)
#   ./wireshark_auth.sh --stream N     Only list the packets of TCP connection N (any mode)
#   ./wireshark_auth.sh --brief        Do not list every packet of every connection
#
# Output (terminal):
#   TLS handshakes      What the client offers and the server chooses, key exchange,
#                       signature, session tickets and the server certificate
#   Packets             Every TCP/TLS/HTTP packet of each connection with direction,
#                       TCP flags, sizes and timing (TCP RTT, TLS handshake, server time)
#   HTTP messages       Decrypted requests/responses with all their headers and bodies
#   Analysis            Secrets, cookies, CSRF, JWTs, refresh tokens, status codes
#   Eavesdropper view   Encrypted bytes per connection
#
# Optional variables:
#   AUTH_PORT=5443                     Port of auth_server.py (decoded as TLS and then HTTP)
#   IFACE=lo                           Capture interface
#   SSLKEYLOGFILE=logs/sslkeys.log     NSS key log used to decrypt the TLS records
#   CAPTURE=/tmp/auth_capture.pcapng   Capture file
#   TSHARK, DUMPCAP, WIRESHARK         Paths to the Wireshark binaries
#
# Notes:
#   - Capturing needs permission to run dumpcap: be in the "wireshark" group
#     (sudo dpkg-reconfigure wireshark-common; sudo usermod -aG wireshark "$USER"
#     and log in again). Otherwise the script falls back to "sudo dumpcap".
#   - The terminal analysis needs tshark (sudo apt install tshark). Without it
#     the capture is opened in the Wireshark GUI.
#   - All the traffic is HTTPS, so on the wire only the TLS handshake, the
#     record sizes and the timing are visible. Python's ssl module (used by
#     requests) and curl write the TLS session secrets to the file named by
#     SSLKEYLOGFILE; the script sets it for test_auth.sh so that Wireshark can
#     decrypt the records and show the HTTP requests. Keep that file private:
#     with it and the capture anyone can read the passwords and tokens.
#   - Wireshark only decodes TLS automatically on well-known ports, so port
#     $AUTH_PORT is decoded as TLS and the decrypted payload as HTTP explicitly.

set -euo pipefail
export LC_NUMERIC=C

PORT="${AUTH_PORT:-5443}"
IFACE="${IFACE:-lo}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
DEFAULT_KEYLOG="$LOGS/sslkeys.log"
KEYLOG="${SSLKEYLOGFILE:-$DEFAULT_KEYLOG}"
CAPTURE="${CAPTURE:-/tmp/auth_capture.pcapng}"
TSHARK="${TSHARK:-$(command -v tshark || true)}"
DUMPCAP="${DUMPCAP:-$(command -v dumpcap || echo /usr/bin/dumpcap)}"
WIRESHARK="${WIRESHARK:-$(command -v wireshark || true)}"

cd "$DIR"

# --- Helpers ----------------------------------------------------------------

GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'; YELLOW=$'\e[33m'; DIM=$'\e[2m'; NORMAL=$'\e[0m'
[ -t 1 ] || { GREEN=""; RED=""; BLUE=""; YELLOW=""; DIM=""; NORMAL=""; }

title() { echo; echo "${BLUE}== $*${NORMAL}"; }
ok()    { echo "${GREEN}[OK]${NORMAL} $*"; }
warn()  { echo "${YELLOW}[WARN]${NORMAL} $*"; }
fail()  { echo "${RED}[FAIL]${NORMAL} $*"; }

usage() {
    sed -n '3,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# Field separator (RS) and separator between repeated values of a field (US).
# Neither is whitespace, so "read" keeps the empty fields.
FS=$'\x1e'; AGG=$'\x1f'

# short <text> [max]: cuts long values (tokens, bodies) for display.
short() {
    local s="$1" n="${2:-70}"
    if [ "${#s}" -le "$n" ]; then echo "$s"; else echo "${s:0:n}..."; fi
}

# hex_to_text <hex>: http.file_data comes as hex bytes.
hex_to_text() {
    [ -n "$1" ] || return 0
    printf '%b' "$(sed 's/../\\x&/g' <<<"$1")" | tr -d '\r' | tr '\n' ' ' | sed 's/ *$//'
}

# b64url_decode <text>: base64url (JWT) without padding.
b64url_decode() {
    local s="${1//-/+}"
    s="${s//_//}"
    while (( ${#s} % 4 )); do s+="="; done
    base64 -d <<<"$s" 2>/dev/null || true
}

# json_get <json> <key>: enough for the flat JSON of a JWT.
json_get() {
    sed -n 's/.*"'"$2"'" *: *"\{0,1\}\([^",}]*\).*/\1/p' <<<"$1" | head -1
}

# header_value <request lines joined by US> <name>
header_value() {
    tr "$AGG" '\n' <<<"$1" | sed -n 's/^'"$2"': *\(.*\)\\r\\n$/\1/Ip' | head -1
}

# count_list <a,b,c>: number of items of a comma-separated list.
count_list() {
    [ -n "$1" ] || { echo 0; return; }
    local commas="${1//[^,]/}"
    echo $(( ${#commas} + 1 ))
}

# ms <seconds> [minus seconds]: difference in milliseconds, 3 decimals.
ms() {
    awk -v a="$1" -v b="${2:-0}" 'BEGIN { printf "%.3f", (a - b) * 1000 }'
}

# tshark_cols <file> <WS_OPTS|WIRE_OPTS> <display filter> <custom columns>
# Custom columns (%Cus) print names ("TLS 1.3", "X25519MLKEM768") instead of
# raw codes; the tabs are turned into $FS so empty columns are kept.
tshark_cols() {
    local -n _opts="$2"
    "$TSHARK" -r "$1" "${_opts[@]}" -Y "$3" -T tabs -o "gui.column.format:$4" \
        2>/dev/null | tr '\t' "$FS"
}

# addr <ipv4> <ipv6> <port>
addr() {
    if [ -n "$1" ]; then echo "$1:$3"; else echo "[$2]:$3"; fi
}

# Wireshark options:
#   WS_OPTS    decode port $PORT as TLS and its payload as HTTP, with the key log
#   WIRE_OPTS  the same without keys: what is really visible on the network
ws_options() {
    local decode=(-d "tcp.port==$PORT,tls" -d "tls.port==$PORT,http")
    WIRE_OPTS=("${decode[@]}" -o "tls.keylog_file:")
    WS_OPTS=("${decode[@]}")
    if [ -n "$KEYLOG" ] && [ -s "$KEYLOG" ]; then
        WS_OPTS+=(-o "tls.keylog_file:$KEYLOG")
        ok "decrypting with the key log $KEYLOG"
    else
        WS_OPTS+=(-o "tls.keylog_file:")
        warn "no key log: only the TLS layer can be analysed"
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

# --- TLS layer (visible without keys) ---------------------------------------

show_tls() {
    local file="$1" cols rows stream a b c d e f k n_conn=0 resumed=0
    local -A CLIENT=() SERVER=() SNIS=() ENC=()
    title "TLS handshakes"

    # --- ClientHello: what the client offers (always in clear) ---
    cols='"Stream","%Cus:tcp.stream"'
    cols+=',"Versions","%Cus:tls.handshake.extensions.supported_version"'
    cols+=',"Suites","%Cus:tls.handshake.ciphersuite"'
    cols+=',"Shares","%Cus:tls.handshake.extensions_key_share_group"'
    cols+=',"Groups","%Cus:tls.handshake.extensions_supported_group"'
    cols+=',"ALPN","%Cus:tls.handshake.extensions_alpn_str"'
    cols+=',"SNI","%Cus:tls.handshake.extensions_server_name"'
    rows="$(tshark_cols "$file" WIRE_OPTS "tls.handshake.type==1" "$cols")"
    if [ -z "$rows" ]; then
        warn "no TLS handshakes on port $PORT in $file"; return 1
    fi
    while IFS="$FS" read -r stream a b c d e f; do
        n_conn=$((n_conn + 1)); SNIS["${f:--}"]=1
        k="versions [$a], $(count_list "$b") cipher suites, ALPN [${e:-none}]"
        k+=$'\n'"          key shares [$c], groups [$(short "$d" 90)]"
        CLIENT["$k"]+=x
    done <<<"$rows"
    echo "  $n_conn connections, SNI: ${!SNIS[*]}"
    echo "  ClientHello ${DIM}(in clear)${NORMAL}: what the client offers"
    for k in "${!CLIENT[@]}"; do printf '    %3d x %s\n' "${#CLIENT[$k]}" "$k"; done

    # --- ServerHello: what the server chooses (always in clear) ---
    cols='"Stream","%Cus:tcp.stream","Version","%Cus:tls.handshake.version"'
    cols+=',"Supported","%Cus:tls.handshake.extensions.supported_version"'
    cols+=',"Suite","%Cus:tls.handshake.ciphersuite"'
    cols+=',"Share","%Cus:tls.handshake.extensions_key_share_group"'
    cols+=',"Ext","%Cus:tls.handshake.extension.type"'
    rows="$(tshark_cols "$file" WIRE_OPTS "tls.handshake.type==2" "$cols")"
    local mlkem=0
    while IFS="$FS" read -r stream a b c d e; do
        [ -n "$stream" ] || continue
        SERVER["${b:-$a}  $c  key exchange ${d:-(RSA/no key share)}"]+=x
        [[ "$e" != *pre_shared_key* ]] || resumed=$((resumed + 1))
        [[ "$d" != *MLKEM* ]] || mlkem=1
    done <<<"$rows"
    echo "  ServerHello ${DIM}(in clear)${NORMAL}: what the server chooses"
    for k in "${!SERVER[@]}"; do printf '    %3d x %s\n' "${#SERVER[$k]}" "$k"; done
    echo "    resumed with a session ticket (PSK): $resumed of $n_conn"
    [ "$mlkem" -eq 0 ] || echo "    ${DIM}X25519MLKEM768 is a hybrid key exchange: classic X25519 plus the"\
        "post-quantum ML-KEM-768, secure if either of the two holds.${NORMAL}"

    # --- Rest of the handshake: encrypted in TLS 1.3, readable with the key log ---
    cols='"Stream","%Cus:tcp.stream","Types","%Cus:tls.handshake.type"'
    cols+=',"Sig","%Cus:tls.handshake.sig_hash_alg"'
    cols+=',"ALPN","%Cus:tls.handshake.extensions_alpn_str"'
    cols+=',"Life","%Cus:tls.handshake.session_ticket_lifetime_hint"'
    rows="$(tshark_cols "$file" WS_OPTS \
        "tls.handshake.type==8 || tls.handshake.type==11 || tls.handshake.type==12 || tls.handshake.type==15 || tls.handshake.type==4" \
        "$cols")"
    local -A SIG=() ALPN=() TICKETS=() LIFE=() CERT=()
    local types t
    while IFS="$FS" read -r stream types a b c; do
        [ -n "$stream" ] || continue
        IFS=',' read -ra t <<<"$types"
        for k in "${t[@]}"; do
            case "$k" in
                "Certificate")                         CERT[$stream]=1 ;;
                "Certificate Verify"|"Server Key Exchange") SIG[$stream]="$a" ;;
                "Encrypted Extensions")                ALPN[$stream]="${b:-none}" ;;
                "New Session Ticket")                  TICKETS[$stream]=$(( ${TICKETS[$stream]:-0} + 1 ))
                                                       LIFE[$stream]="${c%%,*}" ;;
            esac
        done
    done <<<"$rows"
    echo "  Rest of the handshake ${DIM}(encrypted in TLS 1.3: EncryptedExtensions,"\
        "Certificate, CertificateVerify, Finished, NewSessionTicket)${NORMAL}"
    if [ "${#CERT[@]}" -eq 0 ] && [ "${#SIG[@]}" -eq 0 ]; then
        echo "    not readable without the key log"
    else
        for stream in "${!SIG[@]}"; do
            ENC["signature ${SIG[$stream]:-?}, ALPN ${ALPN[$stream]:-none}, ${TICKETS[$stream]:-0} session tickets${LIFE[$stream]:+ (lifetime ${LIFE[$stream]})}"]+=x
        done
        for k in "${!ENC[@]}"; do printf '    %3d x %s\n' "${#ENC[$k]}" "$k"; done
        show_cert "$file"
    fi
}

# Server certificate (from the first Certificate message found).
show_cert() {
    local file="$1" frame
    frame="$("$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "tls.handshake.type==11" \
        -T fields -e frame.number 2>/dev/null | head -1)"
    [ -n "$frame" ] || return 0
    echo "  Server certificate ${DIM}(frame #$frame)${NORMAL}"
    local bits=""
    local mod
    mod="$("$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "frame.number==$frame" \
        -T fields -E occurrence=f -e pkcs1.modulus 2>/dev/null | head -1)"
    mod="${mod#00}"; [ -z "$mod" ] || bits=" $(( ${#mod} * 4 )) bits"

    "$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "frame.number==$frame" -V -O tls 2>/dev/null |
    awk -v bits="$bits" '
        function rdn(s) {
            sub(/.*items? \(/, "", s); sub(/\)$/, "", s)
            gsub(/id-at-commonName=/, "CN=", s);        gsub(/id-at-organizationName=/, "O=", s)
            gsub(/id-at-organizationalUnitName=/, "OU=", s); gsub(/id-at-countryName=/, "C=", s)
            gsub(/id-at-localityName=/, "L=", s);       gsub(/id-at-stateOrProvinceName=/, "ST=", s)
            return s
        }
        /^ *Certificate Length:/   { n++; if (n > 1) print "" ; printf "    certificate %d of the chain (%s bytes)\n", n, $NF }
        /issuer: rdnSequence/      { want = "issuer "; next }
        /subject: rdnSequence/     { want = "subject"; next }
        want && /rdnSequence:/     { printf "      %s  %s\n", want, rdn($0); want = ""; next }
        /notBefore:/               { when = "from" }
        /notAfter:/                { when = "to" }
        when && /(utcTime|generalizedTime):/ {
            sub(/.*Time: /, ""); if (when == "from") from = $0; else printf "      valid    %s -> %s\n", from, $0
            when = ""
        }
        /dNSName:/                 { sub(/.*dNSName: /, "");   san = san (san ? ", " : "") "DNS:" $0 }
        /iPAddress:/               { sub(/.*iPAddress: /, ""); san = san (san ? ", " : "") "IP:" $0 }
        /subjectPublicKeyInfo/     { key = 1; next }
        key && /algorithm \(/      { sub(/.*algorithm \(/, ""); sub(/\).*/, ""); printf "      key      %s%s\n", $0, (n == 1 ? bits : ""); key = 0 }
        /namedCurve:/              { sub(/.*namedCurve: /, ""); printf "      curve    %s\n", $0 }
        /cA: True/                 { print "      CA       yes (can sign other certificates)" }
        /^ *algorithmIdentifier \(/ {
            if (san) { printf "      SAN      %s\n", san; san = "" }
            sub(/.*\(/, ""); sub(/\).*/, ""); printf "      signed   %s by the issuer\n", $0
        }
        /Signature Algorithm: /    { sub(/.*Signature Algorithm: /, ""); cv = $0 }
        END { if (cv) printf "    CertificateVerify: the server proves it owns the key with %s\n", cv }'
}

# Sizes of the encrypted records per connection: what an eavesdropper can measure.
show_wire() {
    local file="$1"
    title "What an eavesdropper sees: encrypted bytes per connection"
    printf '  %-7s %-22s %-22s %s\n' "Stream" "Client -> server" "Server -> client" \
        "${DIM}(decrypted content)${NORMAL}"
    # Without keys a TLS 1.3 record only shows its outer type (opaque_type), so
    # both fields are combined; the custom column keeps the records in order.
    local cols='"Stream","%Cus:tcp.stream","Port","%Cus:tcp.srcport"'
    cols+=',"Type","%Cus:tls.record.content_type||tls.record.opaque_type"'
    cols+=',"Length","%Cus:tls.record.length"'
    "$TSHARK" -r "$file" "${WIRE_OPTS[@]}" -Y "tls" -T tabs -o "gui.column.format:$cols" 2>/dev/null |
    awk -F'\t' -v port="$PORT" '
        {
            n = split($3, types, ","); split($4, lens, ",")
            dir = ($2 == port) ? "s" : "c"
            for (i = 1; i <= n; i++) if (types[i] == "Application Data") { rec[$1, dir]++; bytes[$1, dir] += lens[i] }
            if (!($1 in seen)) { seen[$1] = 1; order[++count] = $1 }
        }
        END { for (i = 1; i <= count; i++) { s = order[i]
            printf "%s\t%d rec %d B\t%d rec %d B\n", s, rec[s, "c"], bytes[s, "c"], rec[s, "s"], bytes[s, "s"] } }' |
    while IFS=$'\t' read -r s c sv; do
        printf '  %-7s %-22s %-22s %s\n' "$s" "$c" "$sv" "${DIM}${STREAM_HTTP[$s]:-?}${NORMAL}"
    done
    echo "  ${DIM}Records include the encrypted part of the TLS 1.3 handshake. Even without"
    echo "  keys, sizes and timing can reveal which endpoint was used and whether a login failed.${NORMAL}"
}

# --- Packets of each TCP connection -----------------------------------------

# us <seconds with decimals>: integer microseconds, without forking awk per packet.
us() {
    local sec="${1%%.*}" frac="${1#*.}"
    [ "$frac" != "$1" ] || frac=0
    frac="${frac}000000"
    echo $(( 10#${sec:-0} * 1000000 + 10#${frac:0:6} ))
}

# fmt_ms <microseconds>
fmt_ms() { printf '%d.%03d' $(( $1 / 1000 )) $(( $1 % 1000 )); }

# Totals and timings of the connection just listed (uses show_packets' variables).
packets_footer() {
    local line="     ${DIM}= $n_pkts packets, payload C->S $bytes_c B, S->C $bytes_s B"
    if [ -n "$t_synack" ]; then
        line+=" | TCP handshake (SYN -> SYN/ACK) $(fmt_ms "$t_synack") ms"
    fi
    if [ -n "$t_ch" ] && [ -n "$t_fin" ]; then
        line+=" | TLS handshake $(fmt_ms $(( t_fin - t_ch ))) ms"
    fi
    [ -z "$t_server" ] || line+=" | server $(fmt_ms "$t_server") ms"
    line+=" | total $(fmt_ms "$t_last") ms${NORMAL}"
    echo "$line"
    if [ -n "$rst" ] && [ -z "$t_synack" ]; then
        line="     ${RED}connection refused (RST): nothing was listening on that address${NORMAL}"
        if [[ "$client_addr" == \[* ]]; then
            line+=" ${DIM}(\"localhost\" is tried as ::1 first; the server only listens on 127.0.0.1)${NORMAL}"
        else
            line+=" ${DIM}(e.g. the server was still starting)${NORMAL}"
        fi
        echo "$line"
    fi
}

show_packets() {
    local file="$1" filter="tcp.port==$PORT"
    [ -z "$ONLY_STREAM" ] || filter+=" && tcp.stream==$ONLY_STREAM"
    title "Packets per TCP connection${ONLY_STREAM:+ (only stream $ONLY_STREAM)}"
    echo "  ${DIM}C = client, S = server. ms = time since the SYN of the connection."
    echo "  Flags: S=SYN A=ACK P=PUSH F=FIN R=RST. Len = TCP payload bytes.${NORMAL}"

    local rows
    rows="$("$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "$filter" -T fields \
        -E separator="$FS" -E occurrence=f \
        -e tcp.stream -e frame.number -e tcp.time_relative \
        -e ip.src -e ipv6.src -e tcp.srcport -e ip.dst -e ipv6.dst -e tcp.dstport \
        -e tcp.len -e tcp.flags.str -e _ws.col.protocol -e _ws.col.info -e http.time \
        2>/dev/null | sort -s -t "$FS" -k1,1n)"
    if [ -z "$rows" ]; then
        warn "no packets match \"$filter\""; return 0
    fi

    local last="" stream num t s4 s6 sport d4 d6 dport plen flags proto info htime
    local n_pkts bytes_c bytes_s t_synack t_ch t_fin t_server t_last rst
    local client_addr server_addr dir color tu f re_ts=' TSval=[0-9]+ TSecr=[0-9]+' re_hdr='^[0-9]+ → [0-9]+ (.*)$'
    while IFS="$FS" read -r stream num t s4 s6 sport d4 d6 dport plen flags proto info htime; do
        if [ "$stream" != "$last" ]; then
            [ -z "$last" ] || packets_footer
            last="$stream"; n_pkts=0; bytes_c=0; bytes_s=0
            t_synack=""; t_ch=""; t_fin=""; t_server=""; t_last=0; rst=""
            echo
            if [ "$dport" = "$PORT" ]; then
                client_addr="$(addr "$s4" "$s6" "$sport")"; server_addr="$(addr "$d4" "$d6" "$dport")"
            else
                client_addr="$(addr "$d4" "$d6" "$dport")"; server_addr="$(addr "$s4" "$s6" "$sport")"
            fi
            echo "  ${BLUE}-- stream $stream${NORMAL}  C $client_addr <-> S $server_addr  ${GREEN}${STREAM_HTTP[$stream]:-}${NORMAL}"
            printf '     %s%-7s %10s  %-6s %-5s %6s  %s%s\n' "$DIM" "Frame" "ms" "Dir" "Flags" "Len" "Info" "$NORMAL"
        fi

        tu="$(us "$t")"; t_last="$tu"; n_pkts=$((n_pkts + 1))
        f="${flags//·/}"
        if [ "$dport" = "$PORT" ]; then
            dir="C -> S"; bytes_c=$((bytes_c + plen))
        else
            dir="C <- S"; bytes_s=$((bytes_s + plen))
            [[ -n "$t_synack" || "$f" != *S* ]] || t_synack="$tu"
        fi
        [[ "$f" != *R* ]] || rst=1

        # TLS handshake: from ClientHello to the client's Finished (seen as
        # "Change Cipher Spec, Application Data" without keys).
        if [[ -z "$t_ch" && "$info" == *"Client Hello"* ]]; then
            t_ch="$tu"
        elif [[ -n "$t_ch" && -z "$t_fin" && "$dir" == "C -> S" && "$info" == *"Change Cipher Spec"* ]]; then
            t_fin="$tu"
        fi

        # Shorter TCP lines: no ports (already in the header) or timestamps.
        if [ "$proto" = "TCP" ]; then
            [[ ! "$info" =~ $re_hdr ]] || info="${BASH_REMATCH[1]}"
            [[ ! "$info" =~ $re_ts ]]  || info="${info/"${BASH_REMATCH[0]}"/}"
            info="${info/ Len=0/}"
        fi
        if [ -n "$htime" ]; then
            t_server="$(us "$htime")"
            info+="  [server took $(fmt_ms "$t_server") ms]"
        fi

        case "$proto" in
            _|"") color="" ;;
            HTTP*) color="$GREEN" ;;
            TLS*|SSL*) color="$BLUE" ;;
            *) color="$DIM" ;;
        esac
        [[ "$f" != *R* ]] || color="$RED"
        printf '     %-7s %10s  %-6s %-5s %6s  %s\n' "#$num" "$(fmt_ms "$tu")" "$dir" "$f" "$plen" \
            "${color}$(short "$proto: $info" 110)${NORMAL}"
    done <<<"$rows"
    packets_footer
}

# --- HTTP layer (needs the key log) -----------------------------------------

declare -A STREAM_HTTP=()   # stream -> "POST /login -> 401"

# Reads the decrypted HTTP messages once and fills the arrays used by the
# listing and the analysis.
HTTP_ROWS=""
load_http() {
    local file="$1"
    HTTP_ROWS="$("$TSHARK" -r "$file" "${WS_OPTS[@]}" -Y "http" -T fields \
        -E separator="$FS" -E occurrence=a -E aggregator="$AGG" \
        -e frame.number -e tcp.stream -e http.request.method -e http.request.uri \
        -e http.response.code -e http.response.phrase -e http.request_in \
        -e frame.time_relative -e http.request.version -e http.response.version -e http.time \
        -e http.cookie -e http.set_cookie -e http.authorization -e http.www_authenticate \
        -e http.request.line -e http.response.line -e http.file_data -e json.member_with_value \
        2>/dev/null || true)"
    [ -n "$HTTP_ROWS" ] || return 1

    # Label of each TCP connection ("POST /login -> 401") for the packet listing.
    local num stream method uri code phrase req_in rest
    local -A m=() u=()
    while IFS="$FS" read -r num stream method uri code phrase req_in rest; do
        if [ -n "$method" ]; then
            m[$num]="$method"; u[$num]="$uri"
        else
            STREAM_HTTP[$stream]="${m[$req_in]:-?} ${u[$req_in]:-$uri} -> $code $phrase"
        fi
    done <<<"$HTTP_ROWS"
}

# print_headers <header lines joined by US>: one per line, the ones that carry
# authentication data highlighted.
print_headers() {
    local h
    while IFS= read -r h; do
        h="${h%\\r\\n}"
        [ -n "$h" ] || continue
        case "${h%%:*}" in
            [Cc]ookie|[Ss]et-[Cc]ookie|[Aa]uthorization|[Oo]rigin|[Ww][Ww][Ww]-[Aa]uthenticate)
                echo "      ${YELLOW}$(short "$h" 110)${NORMAL}" ;;
            *)  echo "      ${DIM}$(short "$h" 110)${NORMAL}" ;;
        esac
    done < <(tr "$AGG" '\n' <<<"$1")
}

show_http_and_analyse() {
    title "Decrypted HTTP messages"
    local num stream method uri code phrase req_in t req_ver resp_ver htime
    local cookie setc auth wwwa lines resp_lines body members
    local -A METHOD=() URI=() R_ORIGIN=() R_HOST=() R_COOKIE=() R_AUTH=() R_REFRESH=()
    local -A ISSUED_ACCESS=() ISSUED_REFRESH=() REFRESH_USES=() COOKIE_USES=()
    local -A TIMES=()
    local -a COOKIE_ORDER=() SECRETS=() COOKIES=() CSRF=() BEARER=() REFRESH=() STATUS=()
    local origin host req what m key value

    echo "  ${DIM}Yellow headers carry authentication data. t = seconds since the start of the capture.${NORMAL}"
    while IFS="$FS" read -r num stream method uri code phrase req_in t req_ver resp_ver htime \
            cookie setc auth wwwa lines resp_lines body members; do
        local body_len=$(( ${#body} / 2 ))
        body="$(hex_to_text "$body")"
        t="$(printf '%.6f' "${t:-0}")"
        if [ -n "$method" ]; then
            # ---------------- Request ----------------
            METHOD[$num]="$method"; URI[$num]="$uri"
            origin="$(header_value "$lines" Origin)"; host="$(header_value "$lines" Host)"
            R_ORIGIN[$num]="$origin"; R_HOST[$num]="$host"
            R_COOKIE[$num]="$cookie"; R_AUTH[$num]="$auth"
            echo
            echo "${BLUE}#$num${NORMAL}  t=$t  stream $stream  C -> S  ${GREEN}$method $uri $req_ver${NORMAL}"
            print_headers "$lines"
            [ -z "$body" ] || echo "      Body ($body_len B): $(short "$body" 100)"

            # Secrets that only TLS protects
            [ -z "$cookie" ] || SECRETS+=("#$num $method $uri|Cookie header|$(short "$cookie" 50)")
            [ -z "$auth" ]   || SECRETS+=("#$num $method $uri|Authorization header|$(short "$auth" 50)")
            while IFS= read -r m; do
                key="${m%%:*}"; value="${m#*:}"
                case "$key" in
                    password|code|refresh_token|access_token|token|secret)
                        SECRETS+=("#$num $method $uri|body \"$key\"|$(short "$value" 50)") ;;
                esac
                [ "$key" != refresh_token ] || R_REFRESH[$num]="$value"
            done < <(tr "$AGG" '\n' <<<"$members" | grep . || true)
            continue
        fi

        # ---------------- Response ----------------
        req="${req_in:-?}"; method="${METHOD[$req]:-?}"; uri="${URI[$req]:-$uri}"
        local color="$GREEN"; [ "${code:-0}" -lt 400 ] || color="$RED"
        echo "${BLUE}#$num${NORMAL}  t=$t  stream $stream  C <- S  ${color}$resp_ver $code $phrase${NORMAL}" \
             "${DIM}(answer to #$req $method $uri${htime:+, server time $(ms "$htime") ms})${NORMAL}"
        print_headers "$resp_lines"
        [ -z "$body" ] || echo "      Body ($body_len B): $(short "$body" 100)"
        STATUS+=("$method $uri -> $code $phrase")
        [ -z "$htime" ] || TIMES["$method $uri -> $code"]+=" $(ms "$htime")"

        # Tokens issued by the server
        while IFS= read -r m; do
            key="${m%%:*}"; value="${m#*:}"
            case "$key" in
                access_token)  ISSUED_ACCESS["$value"]="$num" ;;
                refresh_token) ISSUED_REFRESH["$value"]="$num" ;;
            esac
        done < <(tr "$AGG" '\n' <<<"$members" | grep . || true)

        # Cookies set or deleted by the server
        while IFS= read -r m; do
            [ -n "$m" ] || continue
            COOKIES+=("$num|$method $uri|$m")
        done < <(tr "$AGG" '\n' <<<"$setc")

        # Which response each session cookie got
        if [ -n "${R_COOKIE[$req]:-}" ]; then
            [ -n "${COOKIE_USES[${R_COOKIE[$req]}]:-}" ] || COOKIE_ORDER+=("${R_COOKIE[$req]}")
            COOKIE_USES["${R_COOKIE[$req]}"]+="    #$req $method $uri -> $code"$'\n'
        fi

        # CSRF: state-changing request whose Origin is not the site itself
        origin="${R_ORIGIN[$req]:-}"
        if [ -n "$origin" ] && [ "$origin" != "https://${R_HOST[$req]:-}" ]; then
            CSRF+=("$req|$method $uri|$origin|$code")
        fi

        # Bearer tokens presented to the API
        if [[ "${R_AUTH[$req]:-}" == Bearer\ * ]]; then
            BEARER+=("$req|$method $uri|${R_AUTH[$req]#Bearer }|$code")
        elif [ -n "$wwwa" ]; then
            BEARER+=("$req|$method $uri||$code")
        fi

        # Refresh tokens
        if [ -n "${R_REFRESH[$req]:-}" ]; then
            value="${R_REFRESH[$req]}"
            REFRESH_USES["$value"]=$(( ${REFRESH_USES["$value"]:-0} + 1 ))
            REFRESH+=("$req|$value|${ISSUED_REFRESH[$value]:-}|${REFRESH_USES[$value]}|$code")
        fi
    done <<<"$HTTP_ROWS"

    # ------------------------------------------------------------------------
    title "Analysis: secrets protected only by TLS"
    if [ "${#SECRETS[@]}" -eq 0 ]; then
        echo "  none found"
    else
        for m in "${SECRETS[@]}"; do
            IFS='|' read -r req what value <<<"$m"
            printf '  %-28s %-22s %s\n' "$req" "$what" "${YELLOW}$value${NORMAL}"
        done
        echo "  ${DIM}Readable here only thanks to the key log. Over plain HTTP anyone on the"
        echo "  path would see them: never send credentials or session tokens without TLS.${NORMAL}"
    fi

    title "Analysis: session cookies"
    local prev="" name val attrs a
    for m in "${COOKIES[@]}"; do
        IFS='|' read -r num what value <<<"$m"
        name="${value%%=*}"; val="${value#*=}"; val="${val%%;*}"; attrs="${value#*;}"
        if [[ "$attrs" =~ [Mm]ax-[Aa]ge=0([^0-9]|$) ]] || [[ "$attrs" == *1970* ]]; then
            echo "  #$num $what: ${YELLOW}deletes${NORMAL} $name (expired cookie)"
            continue
        fi
        echo "  #$num $what: sets $name=$(short "$val" 16)"
        for a in Secure HttpOnly "SameSite=" "Path=/"; do
            if [[ "$attrs" == *"$a"* ]]; then
                [ "$a" != "SameSite=" ] || a="$(grep -o 'SameSite=[A-Za-z]*' <<<"$attrs")"
                echo "      ${GREEN}[OK]${NORMAL}   $a"
            else
                echo "      ${RED}[FAIL]${NORMAL} missing $a"
            fi
        done
        if [[ "$name" == __Host-* ]]; then
            if [[ "$attrs" == *Domain=* ]]; then
                echo "      ${RED}[FAIL]${NORMAL} __Host- cookie must not have Domain"
            else
                echo "      ${GREEN}[OK]${NORMAL}   __Host- prefix: Secure, Path=/ and no Domain (bound to this host)"
            fi
        fi
        if [ -n "$prev" ]; then
            if [ "$prev" != "$val" ]; then
                echo "      ${GREEN}[OK]${NORMAL}   new session ID, different from the previous one (anti-fixation)"
            else
                echo "      ${RED}[FAIL]${NORMAL} same session ID as before (session fixation)"
            fi
        fi
        prev="$val"
    done
    [ "${#COOKIES[@]}" -gt 0 ] || echo "  no Set-Cookie headers"

    if [ "${#COOKIE_USES[@]}" -gt 0 ]; then
        echo "  Requests made with each session cookie:"
        for m in "${COOKIE_ORDER[@]}"; do
            echo "  $(short "$m" 40)"
            printf '%s' "${COOKIE_USES[$m]}"
        done
    fi

    title "Analysis: CSRF (requests from another Origin)"
    if [ "${#CSRF[@]}" -eq 0 ]; then
        echo "  no cross-origin requests"
    fi
    for m in "${CSRF[@]}"; do
        IFS='|' read -r req what origin code <<<"$m"
        if [ "$code" -ge 400 ]; then
            echo "  ${GREEN}[OK]${NORMAL}   #$req $what with Origin $origin -> $code (rejected)"
        else
            echo "  ${RED}[FAIL]${NORMAL} #$req $what with Origin $origin -> $code (accepted)"
        fi
    done

    title "Analysis: Bearer tokens (JWT)"
    local token header payload sig alg verdict expected i issued
    [ "${#BEARER[@]}" -gt 0 ] || echo "  no Authorization: Bearer headers"
    for m in "${BEARER[@]}"; do
        IFS='|' read -r req what token code <<<"$m"
        if [ -z "$token" ]; then
            echo "  #$req $what without token -> $code ${DIM}(WWW-Authenticate asks for one)${NORMAL}"
            continue
        fi
        IFS='.' read -r header payload sig <<<"$token"
        header="$(b64url_decode "$header")"; payload="$(b64url_decode "$payload")"
        alg="$(json_get "$header" alg)"
        expected="accept"
        if [ -n "${ISSUED_ACCESS[$token]:-}" ]; then
            verdict="issued by the server in #${ISSUED_ACCESS[$token]}"
        elif [ "${alg,,}" = "none" ] || [ -z "$sig" ]; then
            verdict="FORGED: alg=$alg and no signature"; expected="reject"
        else
            verdict="FORGED: not issued by the server"; expected="reject"
            for issued in "${!ISSUED_ACCESS[@]}"; do
                if [ "${issued##*.}" = "$sig" ]; then
                    verdict="FORGED: payload changed, signature copied from #${ISSUED_ACCESS[$issued]}"
                fi
            done
        fi
        echo "  #$req $what -> $code"
        echo "      header:  $header"
        echo "      payload: $(short "$payload" 140)"
        i="$(json_get "$payload" iat)"; a="$(json_get "$payload" exp)"
        [[ -z "$i" || -z "$a" ]] || echo "      lifetime: $((a - i)) s (exp - iat)"
        if [ "$expected" = "reject" ]; then
            if [ "$code" -ge 400 ]; then
                echo "      ${GREEN}[OK]${NORMAL}   $verdict -> rejected"
            else
                echo "      ${RED}[FAIL]${NORMAL} $verdict -> ACCEPTED"
            fi
        else
            echo "      ${DIM}$verdict${NORMAL}"
        fi
    done
    [ "${#BEARER[@]}" -eq 0 ] || echo "  ${DIM}A JWT is only base64url: anyone who intercepts it can read its claims.${NORMAL}"

    title "Analysis: refresh token rotation"
    [ "${#REFRESH[@]}" -gt 0 ] || echo "  no refresh_token requests"
    local uses
    for m in "${REFRESH[@]}"; do
        IFS='|' read -r req value issued uses code <<<"$m"
        what="#$req refresh with $(short "$value" 16)${issued:+ (issued in #$issued)}"
        if [ "$uses" -gt 1 ]; then
            if [ "$code" -ge 400 ]; then
                echo "  ${GREEN}[OK]${NORMAL}   $what, use #$uses = REUSE -> $code (rejected)"
            else
                echo "  ${RED}[FAIL]${NORMAL} $what, use #$uses = REUSE -> $code (accepted)"
            fi
        elif [ "$code" -ge 400 ]; then
            echo "  ${YELLOW}[INFO]${NORMAL} $what, first use -> $code (family revoked after a reuse, or expired)"
        else
            echo "  ${GREEN}[OK]${NORMAL}   $what, first use -> $code (new token pair)"
        fi
    done

    title "Responses per endpoint"
    printf '%s\n' "${STATUS[@]}" | sort | uniq -c | sort -k2 | sed 's/^/ /'

    title "Server time per endpoint (request -> response, ms)"
    for m in "${!TIMES[@]}"; do
        printf '  %-36s %s\n' "$m" "${TIMES[$m]# }"
    done | sort
    echo "  ${DIM}Login takes about the same with a wrong password and with an unknown user:"
    echo "  the server hashes a dummy password so the timing does not reveal valid users.${NORMAL}"
}

# --- Display ----------------------------------------------------------------

show_terminal() {
    local file="$1" decrypted=0
    show_tls "$file" || return 0
    load_http "$file" && decrypted=1
    [ "$BRIEF" -eq 1 ] || show_packets "$file"
    if [ "$decrypted" -eq 1 ]; then
        show_http_and_analyse
    else
        title "Decrypted HTTP messages"
        warn "no HTTP could be decrypted: everything after the handshake is Application Data"
        echo "  Run without --no-keys, or give the key log: SSLKEYLOGFILE=keys.log $0 --read $file"
    fi
    show_wire "$file"
}

show_gui() {
    local file="$1"
    [ -n "$WIRESHARK" ] || { fail "wireshark not found"; exit 1; }
    ok "opening $file in Wireshark with the filter \"http || tls.handshake\""
    "$WIRESHARK" -r "$file" "${WS_OPTS[@]}" -Y "http || tls.handshake" >/dev/null 2>&1 &
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
BRIEF=0
ONLY_STREAM=""
MODE="test"
READ_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gui)     USE_GUI=1 ;;
        --no-keys) KEYLOG="" ;;
        --live)    MODE="live" ;;
        --brief)   BRIEF=1 ;;
        --stream)  ONLY_STREAM="${2:-}"; [[ "$ONLY_STREAM" =~ ^[0-9]+$ ]] || usage; shift ;;
        --read)    MODE="read"; READ_FILE="${2:-}"; [ -n "$READ_FILE" ] || usage; shift ;;
        -h|--help|*) usage ;;
    esac
    shift
done

mkdir -p "$LOGS"

case "$MODE" in
    read)
        [ -f "$READ_FILE" ] || { fail "cannot find $READ_FILE"; exit 1; }
        show "$READ_FILE"
        ;;

    live)
        if [ "$USE_GUI" -eq 1 ]; then
            # Wireshark captures by itself (it also runs dumpcap).
            ws_options
            ok "live capture in Wireshark: tcp port $PORT on $IFACE, filter \"http || tls.handshake\""
            "$WIRESHARK" -i "$IFACE" -k -f "tcp port $PORT" "${WS_OPTS[@]}" \
                -Y "http || tls.handshake" >/dev/null 2>&1 &
            exit 0
        fi
        title "Live capture"
        choose_dumpcap
        start_capture "$CAPTURE"
        echo "Generate traffic in another terminal, writing the TLS keys to the key log, e.g.:"
        echo "  cd $DIR && SSLKEYLOGFILE=${KEYLOG:-$DEFAULT_KEYLOG} ./test_auth.sh"
        echo "  SSLKEYLOGFILE=${KEYLOG:-$DEFAULT_KEYLOG} curl --cacert $DIR/ca.pem https://localhost:$PORT/profile"
        echo "Press Ctrl+C to stop the capture."
        trap 'echo' INT
        wait "$CAPTURE_PID" 2>/dev/null || true
        trap - INT
        stop_capture
        show "$CAPTURE"
        ;;

    test)
        [ -x "$DIR/test_auth.sh" ] || { fail "cannot find test_auth.sh in $DIR"; exit 1; }
        title "Capture"
        choose_dumpcap
        start_capture "$CAPTURE"
        title "Running test_auth.sh to generate traffic"
        rc=0
        if [ -n "$KEYLOG" ]; then
            [ "$KEYLOG" != "$DEFAULT_KEYLOG" ] || rm -f "$KEYLOG"   # only the keys of this run
            ok "the client writes the TLS keys to $KEYLOG"
            AUTH_PORT="$PORT" SSLKEYLOGFILE="$KEYLOG" "$DIR/test_auth.sh" || rc=$?
        else
            warn "--no-keys: the TLS keys are not saved, the capture cannot be decrypted"
            env -u SSLKEYLOGFILE AUTH_PORT="$PORT" "$DIR/test_auth.sh" || rc=$?
        fi
        stop_capture
        [ "$rc" -eq 0 ] || warn "test_auth.sh finished with code $rc"
        ok "capture saved in $CAPTURE"
        show "$CAPTURE"
        ;;
esac
