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
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
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
    local file="$1"
    title "TLS connections (visible without keys)"
    # Custom columns (%Cus) print names ("TLS 1.3") instead of raw codes.
    local cols='"Stream","%Cus:tcp.stream"'
    cols+=',"Version","%Cus:tls.handshake.version"'
    cols+=',"Supported","%Cus:tls.handshake.extensions.supported_version"'
    cols+=',"Suite","%Cus:tls.handshake.ciphersuite"'
    cols+=',"ALPN","%Cus:tls.handshake.extensions_alpn_str"'
    cols+=',"SNI","%Cus:tls.handshake.extensions_server_name"'
    local tls_rows
    tls_rows="$("$TSHARK" -r "$file" "${WIRE_OPTS[@]}" -T tabs -o "gui.column.format:$cols" \
        -Y "tls.handshake.type==1 || tls.handshake.type==2" 2>/dev/null | tr '\t' "$FS")"
    if [ -z "$tls_rows" ]; then
        warn "no TLS handshakes on port $PORT in $file"; return 1
    fi

    local stream ver supported suite alpn sni n_conn=0
    local -A SNIS=() SERVER=()
    while IFS="$FS" read -r stream ver supported suite alpn sni; do
        if [ -n "$sni" ]; then                      # ClientHello
            n_conn=$((n_conn + 1)); SNIS["$sni"]=1
        else                                        # ServerHello
            SERVER["${supported:-$ver}  $suite${alpn:+  ALPN=$alpn}"]+=x
        fi
    done <<<"$tls_rows"
    echo "  $n_conn TLS connections, SNI: ${!SNIS[*]}"
    local k
    for k in "${!SERVER[@]}"; do
        printf '  %3d x %s\n' "${#SERVER[$k]}" "$k"
    done
    echo "  ${DIM}The server name (SNI) travels in clear in the ClientHello; the URLs,"
    echo "  headers and bodies are inside the encrypted Application Data records.${NORMAL}"
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
        -e http.cookie -e http.set_cookie -e http.authorization -e http.www_authenticate \
        -e http.request.line -e http.file_data -e json.member_with_value 2>/dev/null || true)"
    [ -n "$HTTP_ROWS" ]
}

show_http_and_analyse() {
    title "Decrypted HTTP messages"
    local num stream method uri code phrase req_in cookie setc auth wwwa lines body members
    local -A METHOD=() URI=() R_ORIGIN=() R_HOST=() R_COOKIE=() R_AUTH=() R_REFRESH=()
    local -A ISSUED_ACCESS=() ISSUED_REFRESH=() REFRESH_USES=() COOKIE_USES=()
    local -a COOKIE_ORDER=() SECRETS=() COOKIES=() CSRF=() BEARER=() REFRESH=() STATUS=()
    local origin host req what m key value

    while IFS="$FS" read -r num stream method uri code phrase req_in cookie setc auth wwwa lines body members; do
        body="$(hex_to_text "$body")"
        if [ -n "$method" ]; then
            # ---------------- Request ----------------
            METHOD[$num]="$method"; URI[$num]="$uri"
            origin="$(header_value "$lines" Origin)"; host="$(header_value "$lines" Host)"
            R_ORIGIN[$num]="$origin"; R_HOST[$num]="$host"
            R_COOKIE[$num]="$cookie"; R_AUTH[$num]="$auth"
            echo "${BLUE}#$num${NORMAL} stream $stream  -> ${GREEN}$method $uri${NORMAL}"
            [ -z "$origin" ] || echo "      Origin: $origin"
            [ -z "$cookie" ] || echo "      Cookie: $(short "$cookie")"
            [ -z "$auth" ]   || echo "      Authorization: $(short "$auth")"
            [ -z "$body" ]   || echo "      Body: $(short "$body" 100)"

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
        echo "${BLUE}#$num${NORMAL} stream $stream  <- ${color}$code $phrase${NORMAL}  ${DIM}($method $uri, request #$req)${NORMAL}"
        while IFS= read -r m; do echo "      Set-Cookie: $(short "$m" 100)"; done < <(tr "$AGG" '\n' <<<"$setc" | grep . || true)
        [ -z "$wwwa" ] || echo "      WWW-Authenticate: $wwwa"
        [ -z "$body" ] || echo "      Body: $(short "$body" 100)"
        STREAM_HTTP[$stream]="$method $uri -> $code"
        STATUS+=("$method $uri -> $code $phrase")

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
}

# --- Display ----------------------------------------------------------------

show_terminal() {
    local file="$1"
    show_tls "$file" || return 0
    if load_http "$file"; then
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
MODE="test"
READ_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gui)     USE_GUI=1 ;;
        --no-keys) KEYLOG="" ;;
        --live)    MODE="live" ;;
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
