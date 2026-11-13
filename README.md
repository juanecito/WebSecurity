# TLS 1.2 and TLS 1.3 in depth

Nov 4, 2026 · @Juan Maria Gomez Lopez (juan-maria.gomez-lopez@tutamail.com)

## What TLS is and what it guarantees

HTTPS is HTTP inside a TLS tunnel, usually over TCP on port 443. TLS 1.3 does the same job as TLS 1.2 in half the round trips, encrypts almost the entire handshake and removes the insecure options.

TLS provides three guarantees:

- **Confidentiality:** nobody in the middle can read the traffic.
- **Integrity:** any modification is detected and the connection is torn down.
- **Authentication:** the certificate proves you are talking to the owner of the domain. With mTLS, the server also verifies the client.

TLS has two parts:

- **Handshake protocol:** negotiates the version and algorithms, authenticates the server and agrees on keys.
- **Record protocol:** splits the data into records of up to 16 KB and encrypts them with the agreed keys.

In this document's diagrams, `{...}` marks messages encrypted with handshake keys and `[...]` marks messages encrypted with application keys.

## Certificates and the chain of trust

TLS encryption is worthless if you are talking to the wrong party: the X.509 certificate is what proves that the server's public key belongs to the domain you asked for, and that proof rests on a chain of signatures ending at a root CA your system already trusts.

### What a certificate contains

| Field | What it is | Example |
| --- | --- | --- |
| Subject | Who it belongs to | `CN=example.com` |
| Issuer | Who signed it | `CN=R11, O=Let's Encrypt` |
| Validity | `notBefore` and `notAfter` | 90 days at Let's Encrypt |
| Subject Public Key Info | The public key and its algorithm | ECDSA P-256 or RSA 2048 |
| Subject Alternative Name (SAN) | The names it covers | `DNS:example.com, DNS:*.example.com` |
| Basic Constraints | Whether it can sign other certificates | `CA:FALSE` on a server certificate |
| Key Usage / Extended Key Usage | What the key may be used for | `digitalSignature`, `serverAuth` |
| CRL Distribution Points / AIA | Where to check revocation and fetch the intermediate | CA URLs |
| SCTs | Proof that it is in the Certificate Transparency logs | Two or more log signatures |

### What the client checks

Chain validation is defined in RFC 5280 and name checking in RFC 9525:

1. **Build the chain:** leaf → intermediate(s) → root from the system or browser store. The server must send the intermediates; the root does not need to be sent.
2. **Signatures:** each certificate is signed by the key of the next one.
3. **Constraints:** intermediates have `CA:TRUE` and `keyCertSign`; the leaf has `serverAuth` in Extended Key Usage. Python 3.13 and browsers reject chains that do not meet this (which is why the test certificates in the appendices carry these extensions).
4. **Dates:** the current time is between `notBefore` and `notAfter` for every link.
5. **Name:** the requested domain appears in the SAN. The CN field is no longer used for this. A wildcard covers only one label: `*.example.com` matches `www.example.com` but not `example.com` or `a.b.example.com`.
6. **Revocation:** the certificate has not been revoked (see below).
7. **Certificate Transparency:** Chrome and Safari require SCTs from several independent logs; without them the certificate is rejected even if the signature is valid.

### Revocation: CRLs, OCSP and why certificate lifetimes are shrinking

- **CRL:** the CA publishes the signed list of revoked serial numbers. Browsers no longer download it on each connection; they receive aggregated summaries instead (CRLSets in Chrome, CRLite in Firefox).
- **OCSP:** the client asks the CA about one specific certificate. That tells the CA which sites you visit, so *OCSP stapling* was invented: the server attaches the signed response during the handshake. Let's Encrypt stopped including OCSP URLs in May 2025 and shut down its OCSP servers on 6 August 2025, for privacy and cost reasons; it now publishes CRLs only.
- **Short lifetimes:** because revocation works poorly at scale, the industry's answer is for certificates to expire sooner. CA/Browser Forum ballot SC-081v3 (April 2025) cuts the maximum validity from 398 days to 200 days from 15 March 2026, 100 days from 15 March 2027 and 47 days from 15 March 2029. In practice this forces automatic renewal with ACME (RFC 8555): certbot, acme.sh or the server itself (Caddy, Traefik).

These limits apply to certificates from public CAs. A private CA, like the one in the appendices or a company's own, sets its own rules, but its roots must be installed by hand on every client.

### Checking a chain with OpenSSL

```bash
# Show the chain the server sends and the verification result
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null \
  | grep -E 's:|i:|Verify return code'

# Verify a certificate against a specific CA and intermediate
openssl verify -CAfile root.pem -untrusted intermediate.pem server.pem

# Show the relevant extensions
openssl x509 -in server.pem -noout -ext subjectAltName,basicConstraints,keyUsage,extendedKeyUsage
```

## TLS 1.2: full handshake with ECDHE

A full TLS 1.2 handshake costs two round trips (2-RTT) before the first HTTP request can be sent. This is the most common case, with a suite such as `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.

&#91;embedded content: TLS 1.2 handshake with ECDHE · 11 messages in 2 RTT\]

### What each message does

- **ClientHello / ServerHello:** each side sends 32 random bytes (`client_random`, `server_random`). The client offers suites and extensions, and the server picks one.
- **Certificate:** the certificate travels **in the clear**. Anyone watching the traffic can see which server you connect to.
- **ServerKeyExchange:** the server's ephemeral ECDHE public key, **signed** with the certificate's private key. That signature stops anyone in the middle from inserting their own key.
- **ServerHelloDone:** the server ends its first flight.
- **ClientKeyExchange:** the client's ECDHE public key. With it, both sides compute the *pre-master secret*.
- **ChangeCipherSpec:** not a handshake message but a separate record type meaning "from here on, I encrypt". It is a historical leftover from SSL.
- **Finished:** contains `verify_data`, a digest of all previous messages. If an attacker altered any of them (for example, removing the strong suites from the ClientHello), the digests do not match and the handshake is aborted.

### Key derivation

TLS 1.2 uses its own PRF (Pseudo-Random Function), based on HMAC-SHA256:

```
master_secret = PRF(pre_master, "master secret", client_random + server_random)   → 48 bytes
key_block     = PRF(master_secret, "key expansion", server_random + client_random)
                → encryption keys, MAC keys and IVs for each direction
verify_data   = PRF(master_secret, "client finished", Hash(handshake messages))   → 12 bytes
```

The *Extended Master Secret* extension (RFC 7627) replaces the randoms with the hash of the whole handshake. This prevents the *triple handshake* attack.

### RSA key exchange and resumption

- **RSA key exchange** (for example `TLS_RSA_WITH_AES_128_GCM_SHA256`): there is no ServerKeyExchange. The client generates the pre-master secret and encrypts it with the certificate's RSA public key. If anyone later obtains that private key, they can decrypt every recorded session: there is no forward secrecy.
- **Resumption:** with a *Session ID* (the server caches the session) or with *Session Tickets* (the server encrypts the state and hands it to the client). Both cut the handshake to 1-RTT. The key that encrypts tickets tends to live a long time and, if it leaks, breaks forward secrecy.
- **Renegotiation:** lets the handshake be repeated inside an open connection. It was a source of vulnerabilities and TLS 1.3 removes it.

### TLS 1.2 details

**Anatomy of a suite name:**

```
TLS_ ECDHE _ RSA _WITH_ AES_128_GCM _ SHA256
     │        │           │             └─ PRF hash (and MAC hash if not AEAD)
     │        │           └─ record cipher
     │        └─ server signature algorithm (certificate type)
     └─ key exchange
```

OpenSSL uses different names for the same suites: `ECDHE-RSA-AES128-GCM-SHA256`. That is the format in the Appendix B output.

**Exactly what ServerKeyExchange signs:** `client_random || server_random || ServerECDHParams` (curve type, group and public point). Including both randoms prevents reusing a signature from another session. What it does **not** sign is the ClientHello's list of suites. That protection relies on Finished alone, and it is the gap that downgrade attacks such as Logjam and FREAK exploited against servers that still accepted export suites.

**Sizes:** the randoms are 32 bytes, `session_id` up to 32 bytes, the master secret 48 bytes and `verify_data` 12 bytes. A record carries at most 2^14 bytes (16 KB) of plaintext.

**Security extensions a TLS 1.2 server must support:**

| Extension | RFC | Purpose |
| --- | --- | --- |
| `renegotiation_info` | 5746 | Binds each renegotiation to the previous connection; without it, text can be injected at the start of the session |
| `extended_master_secret` | 7627 | Derives the master secret from the hash of the whole handshake (*triple handshake* attack) |
| `encrypt_then_mac` | 7366 | With CBC suites, computes the MAC over the ciphertext (Lucky13, padding oracles) |
| `supported_groups` and `signature_algorithms` | 8422, 5246 | Negotiate curves and signature algorithms |
| `server_name` (SNI) and ALPN | 6066, 7301 | Site name and application protocol |
| `session_ticket` | 5077 | Resumption without server-side state |

**Recommended configuration if TLS 1.2 must still be offered:** ECDHE key exchange only (or DHE with groups of at least 2048 bits) and AEAD ciphers. For example, in nginx:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

`ssl_ciphers` only affects TLS 1.2. TLS 1.3 suites are configured separately (`ssl_conf_command Ciphersuites ...`), and their defaults are already secure.

## TLS 1.3: full handshake

TLS 1.3 completes the handshake in a single round trip (1-RTT): the client sends its Diffie-Hellman share in the ClientHello, and everything after the ServerHello, including the certificate, is encrypted.

&#91;embedded content: Full TLS 1.3 handshake · 1 RTT, with optional mTLS\]

### What each message does

- **ClientHello:** versions (`supported_versions`), groups and their `key_share` (for example X25519), signature algorithms (`signature_algorithms`), SNI and ALPN.
- **ServerHello:** the server's `key_share` and the chosen version. From here on both sides have the ECDHE secret and derive the handshake keys.
- **EncryptedExtensions:** the remaining parameters, such as the chosen ALPN. In 1.2 these travelled in the clear in the ServerHello.
- **CertificateRequest:** only if the server asks the client for a certificate (mTLS).
- **Certificate:** the X.509 chain, now encrypted.
- **CertificateVerify:** a signature with the certificate's private key over the hash of **the whole transcript**, not just over the ECDHE key as in 1.2. If the key is RSA, this signature must be RSA-PSS (rsa\_pss\_rsae\_\*); the certificate itself may still be signed by the CA with PKCS#1 v1.5.
- **Finished:** an HMAC over the whole transcript. After the client's Finished, everything uses application keys.

ServerKeyExchange, ClientKeyExchange, ServerHelloDone and ChangeCipherSpec disappear as messages. The server may even send data right after its Finished ("0.5-RTT"), although at that point it has not yet verified the client.

### Compatibility and downgrade protection

- **Disguised version:** to avoid breaking old firewalls and proxies (*middleboxes*), the version field still says `0x0303` (TLS 1.2). The real version is negotiated in the `supported_versions` extension. For the same reason, the client may send a dummy ChangeCipherSpec that is ignored (*middlebox compatibility mode*).
- **Downgrade sentinel:** if a server that supports 1.3 ends up negotiating 1.2, it sets the last 8 bytes of `server_random` to `DOWNGRD\x01`. A 1.3 client that sees this sentinel knows someone tampered with the ClientHello, and aborts. In hex these are 44 4F 57 4E 47 52 44 01; if TLS 1.1 or earlier is negotiated, the last byte is 00. The sentinel works because server\_random is signed (in 1.2, inside ServerKeyExchange).
- **HelloRetryRequest (HRR):** if the server does not accept the `key_share` group, it asks for another. The client repeats the ClientHello and the handshake becomes 2-RTT. That is why clients send key\_shares for the most likely groups.
- **Post-quantum key exchange:** the hybrid group X25519MLKEM768 concatenates an X25519 exchange and an ML-KEM-768 encapsulation, and the secret only falls if both are broken. It protects against anyone recording traffic today to decrypt it later with a quantum computer. It is the default group in Chrome and Edge 131+, Firefox 132+ (desktop), Safari 26, Go 1.24+ and OpenSSL 3.5+. The key\_share grows from 32 bytes to about 1,200, and the ClientHello grows to about 1,300-1,500 bytes, which has broken some firewalls that expected the ClientHello in a single packet. The OpenSSL 3.0 in Ubuntu 24.04 or Debian 12 does not support it yet.

### TLS 1.3 details

**The five TLS 1.3 suites** (RFC 8446, appendix B.4). They only name the AEAD cipher and the key schedule hash:

| Suite | Code | Notes |
| --- | --- | --- |
| `TLS_AES_128_GCM_SHA256` | 0x1301 | Mandatory for every implementation |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | Common default in OpenSSL |
| `TLS_CHACHA20_POLY1305_SHA256` | 0x1303 | Preferred without hardware AES (older phones, small ARM) |
| `TLS_AES_128_CCM_SHA256` | 0x1304 | IoT; disabled by default in OpenSSL |
| `TLS_AES_128_CCM_8_SHA256` | 0x1305 | 8-byte tag; not recommended for general use |

**HelloRetryRequest is not a new message:** it is a ServerHello whose `random` is the SHA-256 of the string "HelloRetryRequest" (`CF21AD74E59A6111...`). In the transcript, the first ClientHello is replaced by a synthetic message containing its hash.

**Exactly what CertificateVerify signs:** 64 bytes of `0x20`, the string `"TLS 1.3, server CertificateVerify"`, a `0x00` byte and the transcript hash up to Certificate. The leading padding and the context string prevent reusing the signature in another protocol or in the other direction (the client uses `"TLS 1.3, client CertificateVerify"`).

**How Finished is computed:**

```
finished_key = HKDF-Expand-Label(handshake_traffic_secret, "finished", "", Hash.length)
verify_data  = HMAC(finished_key, Transcript-Hash(ClientHello ... CertificateVerify))
```

**Middlebox compatibility:** the client fills `legacy_session_id` with 32 random bytes and the server echoes them, and both may send a dummy ChangeCipherSpec (`0x01`) that is ignored. To an old firewall, the handshake looks like a TLS 1.2 resumption.

**Post-handshake client authentication:** if the client sends the `post_handshake_auth` extension, the server can ask it for a certificate later, for example when it enters `/admin`. This replaces the renegotiation used for this in 1.2. HTTP/2 forbids it, so in practice it is rarely used.

## TLS 1.3: key schedule

TLS 1.3 replaces the 1.2 PRF with three HKDF stages. Each stage mixes in a new input and produces its own traffic keys, each bound to the exact handshake messages.

&#91;embedded content: TLS 1.3 key schedule · three HKDF stages\]

- **Extract:** at each stage, `HKDF-Extract` mixes the new input (the PSK, the ECDHE secret or zeros) with the previous stage's secret. Between stages, `Derive-Secret(secret, "derived", "")` is applied.
- **Keys bound to the transcript:** traffic keys come from `Derive-Secret(secret, label, Hash(transcript))`. `c hs traffic` uses the hash of ClientHello+ServerHello; `c ap traffic`, the hash up to the server's Finished.
- **Key and IV:** each *traffic secret* yields `HKDF-Expand-Label(secret, "key", "", length)` and `HKDF-Expand-Label(secret, "iv", "", 12)`, different for each direction.
- **Other secrets from the Master Secret:** the *resumption master secret*, from which ticket PSKs are derived, and the *exporter secret*, which other protocols use to derive keys bound to this TLS session (the tls-exporter channel binding in RFC 9266, EAP-TLS or, over DTLS, WebRTC's SRTP). QUIC does not use the exporter: it takes the handshake and application traffic secrets directly to protect its packets (RFC 9001).
- **KeyUpdate:** on long-lived connections, each side can rotate its application keys (N+1 is derived from N) without repeating the handshake.

ECDHE keys are ephemeral and discarded when the connection closes. This gives **forward secrecy**: stealing the certificate's private key later does not let anyone decrypt recorded traffic, because that key only signs.

#### The exact formulas (RFC 8446, section 7.1)

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)
    where HkdfLabel = uint16(Length) || opaque("tls13 " + Label) || opaque(Context)

Derive-Secret(Secret, Label, Messages) =
    HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)

              0
              |
    PSK ->  HKDF-Extract = Early Secret
              +--> Derive-Secret(., "ext binder" | "res binder", "")  = binder_key
              +--> Derive-Secret(., "c e traffic", ClientHello)      = client_early_traffic_secret
              +--> Derive-Secret(., "e exp master", ClientHello)     = early_exporter_master_secret
              v
        Derive-Secret(., "derived", "")
              |
(EC)DHE ->  HKDF-Extract = Handshake Secret
              +--> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
              +--> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
              v
        Derive-Secret(., "derived", "")
              |
    0 ->    HKDF-Extract = Master Secret
              +--> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
              +--> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
              +--> Derive-Secret(., "exp master",   ClientHello...server Finished)
              +--> Derive-Secret(., "res master",   ClientHello...client Finished)

Record key and IV:
    key = HKDF-Expand-Label(traffic_secret, "key", "", key_length)   # 16 or 32 bytes
    iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)

KeyUpdate:
    application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)

Ticket PSK:
    PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
```

In `HKDF-Extract`, the previous stage's secret acts as the *salt* and the new input as the *input keying material*. Without a PSK, the first stage's input is a string of zeros the length of the hash. `Hash` is SHA-256 or SHA-384, depending on the suite.

You can see these formulas at work: the key file produced by `SSLKEYLOGFILE` (or by the callback in Appendix B) contains exactly `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` and `EXPORTER_SECRET`.

## TLS 1.3: PSK resumption and 0-RTT

With a ticket from an earlier connection, the client can reconnect without validating the certificate again and send the HTTP request in its first flight (0-RTT). The price is that this early data can be replayed.

&#91;embedded content: TLS 1.3 resumption with PSK and 0-RTT data\]

- **The ticket:** after a full connection, the server sends one or more **NewSessionTicket** messages, already encrypted. Each carries an opaque identifier, a lifetime (7 days at most) and a `ticket_age_add` that obfuscates its age.
- **The binder:** the ClientHello's `pre_shared_key` extension includes the ticket and an HMAC computed with the PSK over the ClientHello itself. It proves the client holds the PSK and is not replaying someone else's ticket.
- **No certificate:** the server already authenticated itself in the original connection, so it sends neither Certificate nor CertificateVerify.
- **Forward secrecy:** the recommended mode, `psk_dhe_ke`, mixes the PSK with a fresh ECDHE exchange. The PSK-only mode, `psk_ke`, is faster but has no forward secrecy.
- **EndOfEarlyData:** the client sends it to close the 0-RTT phase and switch to handshake keys.

### The 0-RTT risk

0-RTT data is encrypted with keys derived **from the PSK alone**. It has no forward secrecy and, above all, an attacker can capture that first flight and **replay it**. The usual defences:

- Accept only idempotent methods (GET) in 0-RTT, never a POST that makes a payment.
- Keep an anti-replay cache on the server.
- Use the `Early-Data: 1` header (RFC 8470), which lets a backend reply `425 Too Early`.

Many servers leave 0-RTT disabled by default.

#### Resumption details

- **Binder:** an HMAC computed with a key derived from the PSK (`binder_key`, label `"res binder"` for tickets) over the ClientHello **truncated** just before the list of binders. That is why the `pre_shared_key` extension must be the last one in the ClientHello.
- **Ticket age:** the client sends `obfuscated_ticket_age = (age_in_ms + ticket_age_add) mod 2^32`. The server de-obfuscates it and compares it with the real age; if they differ too much, it rejects 0-RTT (a defence against out-of-window replays).
- **Ticket lifetime:** at most 604,800 seconds (7 days). A PSK can only be used with a suite that has the same hash as the original.
- **How much 0-RTT data:** the ticket states `max_early_data_size`. The server accepts or rejects 0-RTT with the `early_data` extension in EncryptedExtensions. If it rejects it, the client resends that data after the handshake, with normal keys.
- **Anti-replay (RFC 8446, section 8):** single-use tickets, a record of ClientHellos already seen within a time window, and ticket-age checks. None of them prevents replay across several servers that do not share state, so the application must still treat 0-RTT data as replayable.

## The encrypted record: 1.2 vs 1.3

In TLS 1.3, an observer can no longer tell what type of message each record carries, and the nonce is no longer transmitted. The header is still 5 bytes in both versions: type, version and length.

&#91;embedded content: Encrypted record · TLS 1.2 with AES-GCM vs TLS 1.3\]

- **Hidden content type:** in 1.2 you can tell handshake, alert and application records apart. In 1.3, the header always says `application_data` (23) with version `0x0303`, and the real type travels inside the ciphertext.
- **Optional padding:** in 1.3 records can be padded to hide the real message size and make traffic analysis harder.
- **Nonce:** in 1.2 with GCM, 8 bytes of the nonce travelled in every record, and implementations that repeated them broke GCM's security. In 1.3, the nonce is `IV XOR sequence_number`: it takes no space and does not repeat while the counter advances.
- **Sequence number:** it is not transmitted in either version, but it goes into the computation. If a record is reordered or dropped, decryption fails.
- **Authenticated data (AAD):** in 1.3 it is the 5-byte header itself. In 1.2 it was the sequence number, type, version and length.
- **Algorithms:** 1.3 only allows AEAD ciphers (AES-GCM, ChaCha20-Poly1305, AES-CCM). CBC (attacked by Lucky13 and POODLE), RC4 and 3DES are gone.

#### Exact record figures

|  | TLS 1.2 (AES-GCM) | TLS 1.3 |
| --- | --- | --- |
| Maximum plaintext | 2^14 bytes (16,384) | 2^14 bytes, plus the type byte and padding |
| Maximum ciphertext | 2^14 + 2,048 bytes | 2^14 + 256 bytes |
| Nonce | 4 implicit bytes (from the key\_block) + 8 explicit bytes in the record | 12-byte IV XOR 64-bit sequence number |
| Authenticated data (AAD) | 13 bytes: sequence (8) + type (1) + version (2) + length (2) | 5 bytes: the record header |
| Encrypted content | Data only | `TLSInnerPlaintext` = data + real type (1 byte) + zero padding |

ChaCha20-Poly1305 in TLS 1.2 (RFC 7905) already used an implicit nonce like 1.3, with no explicit bytes.

**Per-key usage limit:** RFC 8446 (section 5.5) asks that no more than about 2^24.5 full-size records (about 24 million, roughly 380 GB) be encrypted under the same AES-GCM key. Before reaching that, the implementation sends a KeyUpdate. With ChaCha20-Poly1305 the limit is so high that the sequence number would run out first.

## Summary of differences

| Aspect | TLS 1.2 | TLS 1.3 |
| --- | --- | --- |
| Full handshake | 2-RTT | 1-RTT (2 with a HelloRetryRequest) |
| Resumption | 1-RTT (Session ID or ticket) | 1-RTT with PSK, or 0-RTT |
| Key exchange | RSA, DHE, ECDHE | (EC)DHE or PSK(+DHE) only |
| Forward secrecy | Optional | Always, except psk\_ke and 0-RTT |
| Server signature | Over the DH parameters | Over the whole transcript |
| Key derivation | TLS PRF (HMAC) | Three-stage HKDF |
| Certificate | In the clear | Encrypted |
| Cipher suite | Key exchange + authentication + cipher + MAC | AEAD + hash only |
| Cipher modes | CBC, RC4, 3DES, GCM... | AEAD only |
| Renegotiation | Yes | No (KeyUpdate and post-handshake authentication) |
| Record type | Visible | Hidden, with optional padding |

SSL 3.0, TLS 1.0 and TLS 1.1 are obsolete and should be disabled.

## What TLS does not hide

- The destination **IP address and port**.
- The **SNI**, in the clear in the ClientHello: the domain is visible even though the URL is not. The ECH extension (Encrypted Client Hello, RFC 9849, November 2025) encrypts a complete inner ClientHello, with the real SNI and ALPN, using an HPKE key the server publishes in DNS (HTTPS/SVCB records). From outside, only an outer ClientHello with a generic provider name is visible. Deployment is still partial and also depends on using encrypted DNS.
- The **size and timing** of the traffic.
- The **DNS** lookup, unless you use DoH or DoT.

The path, query parameters, headers, cookies and body are encrypted.

## Checking it in your own traffic

Force each version and see the handshake messages in order. In 1.2 you will see ServerKeyExchange and ServerHelloDone; in 1.3, EncryptedExtensions right after the ServerHello:

```bash
openssl s_client -connect example.com:443 -servername example.com -tls1_2 -msg
openssl s_client -connect example.com:443 -servername example.com -tls1_3 -msg
```

Show the certificate details (issuer, dates, SAN):

```bash
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Export the session keys and load them into Wireshark to decrypt the capture:

```bash
SSLKEYLOGFILE=/tmp/keys.log curl -s https://example.com > /dev/null
```

To audit a server's configuration (versions, ciphers, certificate chain and known vulnerabilities), `testssl.sh` checks everything in one pass.

## Web authentication in depth

Every web authentication scheme solves two separate problems: proving once who you are (login) and then having every later request carry proof of that identity without repeating the login. TLS protects that proof in transit, but does not replace it.

### Core concepts

- **Authentication (AuthN):** verifying who the user is. Answers "who are you?".
- **Authorization (AuthZ):** deciding what they may do. Answers "may you do this?". OAuth 2.0 is mainly an authorization protocol; OpenID Connect adds authentication on top.
- **Factors:** something you know (password, PIN), something you have (phone, security key) and something you are (fingerprint, face). MFA combines at least two different factors.
- **Stateful:** the server stores the session and the client only carries a random identifier. Revocation is immediate: delete the session.
- **Stateless:** the client carries a signed token with all the information and the server only verifies the signature. It scales without a shared store, but revoking before expiry is hard.
- **Bearer credential:** whoever holds it can use it. Session cookies, access tokens and API keys are bearer credentials: if stolen, the attacker can impersonate the user. That is why they must only travel over HTTPS.
- **Bound credential (proof-of-possession):** only works if you also prove you hold a private key. This is the case for mTLS, WebAuthn and DPoP tokens.

### Where the credential travels in HTTP

| Mechanism | Header or location | Sent by |
| --- | --- | --- |
| Session cookie | `Cookie: session=...` | The browser, automatically |
| Access token | `Authorization: Bearer <token>` | The client code, explicitly |
| HTTP Basic | `Authorization: Basic base64(user:password)` | The browser or client |
| API key | `X-API-Key: ...` or `Authorization` | The client |
| Client certificate | Inside the TLS handshake | The client's TLS stack |

&#91;embedded content: Web authentication mechanisms · 3 phases\]

### Passwords: how they are stored and sent

A password is never stored as is, nor encrypted: a slow, salted hash is stored. If the database is stolen, the attacker has to try candidates one by one, and each guess costs time and memory.

**Correct storage:**

- **Algorithm:** Argon2id is the recommended choice. bcrypt and scrypt are acceptable; PBKDF2 only with many iterations or when FIPS (Federal Information Processing Standards) is required.
- **Salt:** a different random value per user, stored next to the hash. It defeats precomputed tables and stops two users with the same password from having the same hash.
- **Cost:** tuned so that verification takes on the order of hundreds of milliseconds. Slow enough to stop a mass attack and fast enough for a normal login.
- **Never:** plain MD5, SHA-1 or SHA-256. They are fast by design, and a GPU tries billions per second.

**Minimum parameters recommended by OWASP:**

| Algorithm | Minimum | Notes |
| --- | --- | --- |
| Argon2id | m = 19 MiB (19,456 KiB), t = 2, p = 1; or m = 46 MiB, t = 1 | First choice. RFC 9106 suggests m = 64 MiB, t = 3 if you can afford it |
| scrypt | N = 2^17, r = 8, p = 1 | If Argon2id is unavailable |
| bcrypt | Cost 10 or higher | Only uses the first 72 bytes of the password |
| PBKDF2 | 600,000 iterations with HMAC-SHA-256 | Only if FIPS 140 is required |

The `argon2-cffi` library used in Appendix C defaults to the RFC 9106 profile (m = 64 MiB, t = 3, p = 4), which is why its hash starts with `$argon2id$v=19$m=65536,t=3,p=4`. Memory is consumed per concurrent login: 100 simultaneous logins at 64 MiB need about 6.4 GB, so measure before raising the parameters. A *pepper* (a shared secret added before hashing and stored outside the database, in a secrets store or HSM) adds protection if only the database is stolen.

A stored Argon2id hash looks like this, with algorithm, parameters, salt and hash in a single string:

```
$argon2id$v=19$m=65536,t=3,p=4$c2FsdGFsZWF0b3JpYQ$hJ3k...
```

**Verification at login:** the server recomputes the hash with the stored salt and compares in constant time. If the user does not exist, it should still compute a dummy hash so the response time does not reveal which users exist.

**Other good practices:** limit attempts per account and per IP, check new passwords against lists of breached passwords, allow long passwords and do not force periodic changes without reason.

#### HTTP Basic and Digest

These are HTTP's native mechanisms. The server replies `401 Unauthorized` with `WWW-Authenticate` and the client repeats the request with `Authorization`.

```
GET /admin HTTP/1.1
← 401 Unauthorized
  WWW-Authenticate: Basic realm="Admin"

GET /admin HTTP/1.1
Authorization: Basic anVhbjpzZWNyZXRv      ← base64("juan:secreto")
← 200 OK
```

- **Basic (RFC 7617):** base64 is not encryption, so the password travels in the clear inside TLS and is sent on **every** request. There is no real logout: the browser remembers it until it is closed. Fine for internal tools or simple APIs, always over HTTPS.
- **Digest (RFC 7616):** sends a hash of the password with a server nonce instead of the password. It forces the server to store the password (or an equivalent fast hash), so it is barely used today: Basic over TLS with a slow hash on the server is more secure.

### Cookie-based sessions

This is the classic mechanism for browser-based web applications: after login, the server stores the session and gives the browser a random identifier in a cookie, which the browser sends back automatically on every request.

&#91;embedded content: Cookie session · login, request and logout\]

#### The flow, step by step

1. **Login:** the user sends username and password with `POST /login`, never with GET (it would end up in logs and history).
2. **Verification:** the server checks the password hash and, if MFA is enabled, asks for the second factor.
3. **Session creation:** it generates an ID with at least 128 bits from a cryptographic generator and stores the user, creation time, last activity time and anything else it needs in the session store (memory, Redis or a database).
4. **Set-Cookie:** it replies with the cookie and its security attributes:

   ```
   Set-Cookie: __Host-session=k3J9xQ...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
   ```
5. **Later requests:** the browser adds `Cookie: __Host-session=k3J9xQ...` to every request to that domain. The server looks up the ID in the store, checks it has not expired and retrieves the user.
6. **Logout:** the server **deletes the session from the store** and replies with an expired cookie. Deleting only the browser cookie is not enough: anyone who copied the ID could keep using it.

#### Cookie attributes

| Attribute | What it does | Protects against |
| --- | --- | --- |
| `Secure` | Only sent over HTTPS | Theft on an unencrypted network |
| `HttpOnly` | JavaScript cannot read it | Session theft via XSS |
| `SameSite=Lax` | From another site, only sent on top-level navigations with a safe method (following a link, GET); not on POST, iframes, images or fetch | CSRF |
| `SameSite=Strict` | Not sent on any request initiated from another site, not even when following a link | CSRF, at the cost of convenience |
| `SameSite=None` | Always sent (requires `Secure`) | Nothing; only for cross-site cases such as third-party iframes |
| `Max-Age` / `Expires` | Expiry in the browser | Forgotten open sessions |
| `Domain` | Extends the cookie to subdomains | Better left out: without it, only the exact host receives it |
| `__Host-` prefix | The browser requires `Secure`, `Path=/` and no `Domain` | A compromised subdomain overwriting the cookie |

Two `SameSite` details that are often confused:

- **Site is not origin.** A *site* is the scheme plus the registrable domain (`https://example.com`); an *origin* also includes the subdomain and port. `app.example.com` and `blog.example.com` are the same site, so `SameSite` does not protect against a compromised subdomain. That is what the `__Host-` prefix and the `Origin` check are for.
- **The default depends on the browser.** Chrome and Edge treat cookies without `SameSite` as `Lax`; Firefox and Safari do not. So always declare it.

#### Typical attacks and defences

- **CSRF (Cross-Site Request Forgery):** a malicious site makes the browser send a request to your application, and the cookie is attached automatically. Defend with `SameSite`, an anti-CSRF token in forms (which the attacker cannot read), and by checking the `Origin` or `Sec-Fetch-Site` headers on state-changing requests.
- **Session fixation:** the attacker gets the victim to use a session ID the attacker knows, then waits for them to log in. Prevent it by **issuing a new ID on authentication** and whenever privileges change.
- **Cookie theft:** via XSS, malware or a compromised proxy. `HttpOnly` closes the XSS route; the rest is mitigated with idle timeouts (for example 30 minutes), absolute timeouts (for example 12 hours) and asking for the password again before critical actions.

**Pros:** immediate revocation, the browser handles it on its own and `HttpOnly` protects it from XSS. **Cons:** needs a session store shared between servers, requires CSRF defences and fits poorly outside the browser (mobile apps, service-to-service APIs).

### Tokens: opaque and JWT

A token is a credential the client sends in the `Authorization: Bearer <token>` header. It can be **opaque** (a random string the server looks up in its database, like a session ID) or **self-contained**, like a JWT, which carries the data inside along with a signature the server verifies without looking anything up.

#### Structure of a JWT (RFC 7519)

Three base64url parts separated by dots: `header.payload.signature`.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqdWFuIiwiZXhwIjoxNzk....SflKxwRJSMeKKF2QT4fwpM...
```

```json
// Header
{ "alg": "RS256", "typ": "JWT", "kid": "key-2026-11" }

// Payload (claims)
{
  "iss": "https://auth.example.com",   // who issued it
  "sub": "user-1234",                  // who it is about
  "aud": "https://api.example.com",    // who it is for
  "iat": 1793780000,                   // issued at (Unix seconds)
  "exp": 1793780900,                   // expires: 15 minutes later
  "jti": "5f2b9c...",                  // unique ID, useful for revocation
  "scope": "orders:read"
}

// Signature
RSASSA-PKCS1-v1_5-SHA256( base64url(header) + "." + base64url(payload), private_key )
```

The payload is **signed, not encrypted**: anyone can read it by decoding the base64url. Never put passwords or sensitive personal data in a JWT. If it needs to be encrypted, there is JWE.

#### Signature algorithms

- **HS256 (HMAC):** one shared secret key. Whoever verifies can also issue, so it only fits when issuer and verifier are the same service.
- **RS256 / PS256 (RSA) and ES256 / EdDSA (elliptic curves):** the issuer signs with its private key and any service verifies with the public one. Public keys are usually published at a JWKS endpoint (`/.well-known/jwks.json`), and the `kid` field says which one to use, which allows rotation.

#### Correct validation: what the server must check

1. That `alg` is the one **you expect**, fixed in code. Never accept whatever the header says: that is how `alg: none` and RS256/HS256 confusion attacks work (signing with HMAC using the RSA public key as the secret).
2. The signature, with the key matching the `kid`.
3. `exp` (not expired) and `nbf` if present, with a small leeway for clock skew.
4. `iss` and `aud`: that it was issued by whom you expect and is addressed to this service. Without this check, a token issued for another API from the same provider would also work on yours.
5. The permissions (`scope`, roles) against the requested operation.

The JWT best practices (RFC 8725) add:

- **Do not follow external keys:** ignore the `jku`, `x5u` and `jwk` headers, which point to a key chosen by whoever sends the token. The verification key comes from your configuration or from the JWKS of the issuer you know.
- **Type your tokens:** RFC 9068 defines `typ: at+jwt` for access tokens. That way an API does not mistakenly accept an OIDC ID token signed by the same issuer.
- **Long HMAC keys:** with HS256, at least 256 random bits. A key like `"secret"` can be brute-forced from a single token.
- **Units:** `exp`, `iat` and `nbf` are seconds since 1970 (NumericDate), not milliseconds.

#### Access tokens and refresh tokens

Because a JWT cannot easily be revoked, two tokens are used:

- **Access token:** short-lived (5-15 minutes), sent with every API request.
- **Refresh token:** long-lived (days), only sent to the refresh endpoint to obtain a new access token. It is opaque and stored on the server, so it **can be revoked**.
- **Rotation:** each time a refresh token is used, a new one is issued and the old one invalidated. If someone tries to reuse an already-used one, that signals theft: the whole token family for that session is revoked.

To revoke an access token before it expires there are two options: a deny list of revoked `jti` values checked on every request (reintroducing state) or simply accepting the risk for its few minutes of life.

#### Where to store tokens in the browser

| Location | XSS risk | CSRF risk | Comment |
| --- | --- | --- | --- |
| `localStorage` / `sessionStorage` | High: any script can read it | No | Most convenient and most exposed |
| In-memory variable (JavaScript) | Medium: an injected script can use it while the page is open | No | Lost on reload; combined with a refresh token in a cookie |
| `HttpOnly; Secure; SameSite` cookie | Low: cannot be read | Yes, mitigated with SameSite | In practice it becomes a session cookie again |

That is why many web applications use the **BFF (Backend for Frontend)** pattern: the browser only holds an `HttpOnly` session cookie, and the application's own backend stores the OAuth tokens and calls the APIs. In mobile and desktop apps, tokens go in the system's secure store (Keychain, Keystore, DPAPI).

### OAuth 2.0 and OpenID Connect

OAuth 2.0 (RFC 6749) lets an application act on behalf of a user without knowing their password: the user authenticates with an authorization server, which gives the application an access token with limited permissions. OpenID Connect (OIDC) adds an **ID token** on top that says who the user is, and it is what sits behind "Sign in with Google" and behind Entra ID, Keycloak and Auth0.

#### Roles

- **Resource owner:** the user.
- **Client:** the application that wants access. It is *confidential* if it can keep a secret (a backend) or *public* if it cannot (an SPA, a mobile app).
- **Authorization server (AS):** authenticates the user and issues the tokens. In OIDC it is called the identity provider (IdP).
- **Resource server:** the API that accepts the access token.

#### Authorization code flow with PKCE

This is the recommended flow for any application with a user, including SPAs and mobile apps. PKCE (RFC 7636) prevents anyone who intercepts the authorization code from redeeming it.

&#91;embedded content: OAuth 2.0 authorization code with PKCE · 9 messages\]

1. **Prepare PKCE:** the application generates a random `code_verifier` (43-128 characters) and computes `code_challenge = BASE64URL(SHA256(code_verifier))`. It also generates a random `state` and, with OIDC, a `nonce`.
2. **Redirect to the AS:**

   ```
   GET https://auth.example.com/authorize?
       response_type=code
       &client_id=my-app
       &redirect_uri=https://app.example.com/callback
       &scope=openid profile orders:read
       &state=Xy7...
       &nonce=Qp2...
       &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
       &code_challenge_method=S256
   ```
3. **Login and consent:** the user authenticates **at the AS**, not at the application, and approves the requested permissions.
4. **Return with the code:** the AS redirects to `https://app.example.com/callback?code=SplxlOB...&state=Xy7...`. The application checks that `state` is the one it generated (CSRF protection for the login).
5. **Code exchange (back channel):** the application calls the AS directly:

   ```
   POST /token
   grant_type=authorization_code&code=SplxlOB...
   &redirect_uri=https://app.example.com/callback
   &client_id=my-app&code_verifier=dBjftJeZ4CVP...
   ```

   The AS computes the SHA-256 of the `code_verifier` and checks that it matches the `code_challenge` from step 2. A confidential client also adds its `client_secret` or authenticates with mTLS or a signed JWT.
6. **Tokens:** the AS replies with `access_token`, `refresh_token`, `expires_in` and, with OIDC, `id_token`.
7. **Call the API** with `Authorization: Bearer <access_token>`.

#### The OpenID Connect ID token

It is a JWT addressed to the application (not the API) describing the login: `sub` (stable user identifier), `iss`, `aud` (the `client_id`), `exp`, `iat`, `nonce`, `auth_time` and data such as `email` or `name` depending on the scopes. The application must validate it like any JWT and check that the `nonce` is the one it sent. To identify the user, use the `iss` + `sub` pair, never the email, which can change.

The AS publishes its configuration at `/.well-known/openid-configuration`: endpoints, JWKS keys, scopes and supported algorithms.

#### Other flows

| Flow | Purpose | Status |
| --- | --- | --- |
| Authorization code + PKCE | Apps with a user: web, SPA, mobile, desktop | Recommended |
| Client credentials | Service to service, no user | Recommended |
| Device authorization (RFC 8628) | Devices without a keyboard: TV, CLI | Recommended |
| Refresh token | Renew the access token | Recommended, with rotation |
| Implicit | Old SPAs; the token came back in the URL | Discouraged |
| Resource owner password | The app asks the user for their password | Discouraged |

The OAuth security best current practice (RFC 9700, January 2025) and the OAuth 2.1 draft (submitted to the IESG in July 2026, not yet published as an RFC) capture these recommendations: PKCE for every client, exact `redirect_uri` matching and no implicit or password flows.

#### OAuth details and extensions

- **PKCE and `state`:** the `code_verifier` uses only the characters `A-Z a-z 0-9 - . _ ~` and is 43 to 128 long. The only acceptable method is `S256`; `plain` protects nothing if the attacker sees the request. According to RFC 9700, a client that knows the AS enforces PKCE may rely on it for CSRF protection; in OIDC, the `nonce` serves that purpose. Even so, `state` is still useful for remembering which page to return to.
- **Mix-up (RFC 9207):** if a client works with several ASes, every authorization response must include the `iss` parameter, and the client checks it matches the AS it sent the user to.
- **PAR (RFC 9126):** the client sends the `/authorize` parameters over the back channel and receives a `request_uri`. The browser URL no longer shows the parameters or allows tampering with them.
- **DPoP (RFC 9449):** binds the access token to a client key. Each request carries a `DPoP` header with a signed JWT that includes the method, URL and time. A stolen token is useless without the private key. It is the alternative to mTLS (RFC 8705) when client certificates cannot be used.
- **Metadata and interoperability:** RFC 8414 (AS metadata), RFC 7662 (opaque token introspection), RFC 7009 (revocation), RFC 9068 (JWT access tokens) and RFC 8693 (token exchange, so a service can request a token on behalf of another).
- **Authorization codes:** single-use and short-lived (10 minutes at most per RFC 6749; about 60 seconds in practice). If someone tries to redeem the same code twice, the AS should revoke the tokens it already issued with it.

### SAML, API keys and mTLS

#### SAML 2.0

The most widespread single sign-on (SSO) standard in corporate environments, older than OIDC and based on XML. The roles are the same under different names: the **IdP** (Entra ID, ADFS, Okta) authenticates the user and the **SP** (*Service Provider*, the application) trusts it.

1. The user opens the application (SP), which redirects them to the IdP with an `AuthnRequest`.
2. The IdP authenticates them, often transparently with Kerberos if they are on the Windows domain.
3. The IdP returns, through the browser (a self-submitting POST form), a **SAML assertion**: a signed XML document with the user, their attributes (groups, email) and its validity.
4. The SP verifies the signature with the IdP's certificate, checks `Audience`, `NotOnOrAfter` and `InResponseTo`, and creates its own cookie session.

The tricky part is validating the XML signature: *XML Signature Wrapping* attacks get one signed fragment validated while the application reads another, injected one. That is why you must use a mature library and never process the XML by hand. New applications usually prefer OIDC, but SAML is still the norm when integrating with corporate directories.

#### API keys

A long random string that identifies a **client** (a script, another service, a paying customer), not a user. It is sent in a header, for example `X-API-Key` or `Authorization: Bearer`.

- **Generate it** with a cryptographic generator (32 bytes or more) and, ideally, with a recognisable prefix (`sk_live_...`) so secret scanners spot it if it leaks into a repository.
- **Store it hashed** (SHA-256 is enough, because it is long and random, not a password) and show it only once, at creation.
- **Scope it:** least privilege, expiry, rotation and, if possible, IP restrictions.
- **Never in the URL** (`?api_key=...`): it ends up in proxy logs, browser history and the `Referer` header.

#### mTLS: client certificates

In mutual TLS, the server sends `CertificateRequest` during the handshake and the client replies with its certificate and a `CertificateVerify` signed with its private key, as shown in the TLS 1.3 diagram. Identity is proven **before** any HTTP request arrives, and the credential cannot be stolen by copying a header: the private key is required.

It is used between microservices (often automatically with a *service mesh* such as Istio or Linkerd), in banking and B2B APIs, in VPNs and in IoT devices. Its cost is running a PKI: issuing, renewing and revoking certificates. With OpenSSL, the server in Appendix B would enable it with `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL)` and by loading the clients' CA; the client would load its certificate and key the same way the server does.

RFC 8705 also lets an OAuth access token be bound to the client certificate: even if the token is stolen, it is useless without the private key.

### Second factor and passkeys

A second factor means a stolen password is not enough. But they do not all protect equally: codes the user types can be captured by a fake site, and only WebAuthn (passkeys and security keys) is phishing-resistant.

#### TOTP: 6-digit codes (RFC 6238)

This is what Google Authenticator, Aegis or Microsoft Authenticator generate.

1. **Enrolment:** the server generates a random secret (usually 160 bits), stores it with the user and shows it as a QR code with a URI like `otpauth://totp/MyApp:juan?secret=JBSWY3DPEHPK3PXP&issuer=MyApp`.
2. **Computation:** the app and the server compute the same thing independently:

   ```
   T    = floor(unix_time / 30)
   HMAC = HMAC-SHA1(secret, T as 8 bytes)
   code = truncate(HMAC) mod 10^6
   ```
3. **Verification:** the server accepts the code for the current interval and, at most, one before and one after for clock skew. It must remember the last code used so it cannot be reused, and limit attempts (with 6 digits there are only a million combinations).

The TOTP secret is symmetric: the server has to store it in a recoverable form, so it is encrypted, not hashed. When the second factor is enabled, single-use recovery codes are handed out, and those are stored hashed.

#### SMS and push notifications

- **SMS:** better than nothing, but vulnerable to SIM duplication (*SIM swapping*) and to interception on the mobile network. It is now discouraged as the only second factor.
- **Push:** the phone app asks "is this you?". It is convenient, but suffers from *MFA fatigue*: the attacker fires off approvals until the user accepts one out of exhaustion. Mitigate it with *number matching*: the user types into the phone the number they see on screen.

#### WebAuthn and passkeys

WebAuthn (W3C) together with CTAP (FIDO2) replace the shared secret with **public-key cryptography**. The server only stores the public key, so if the database is stolen there is nothing to reuse. A *passkey* is a WebAuthn credential that syncs across devices (iCloud Keychain, Google Password Manager, managers like 1Password) and can fully replace the password.

**Registration:**

1. The server sends a random `challenge`, its identifier (`rp.id`, for example `example.com`) and the user's details.
2. The browser calls `navigator.credentials.create()`. The authenticator (Touch ID, Windows Hello, the phone or a YubiKey) asks the user for a gesture, generates a **key pair unique to that site** and returns the public key and a credential ID.
3. The server stores the public key, the credential ID and a signature counter.

**Login:**

&#91;embedded content: WebAuthn / passkey login\]

1. The server sends a new `challenge`.
2. The browser calls `navigator.credentials.get()`. The authenticator asks for a fingerprint, face or PIN and **signs** the challenge together with the page's real origin.
3. The server verifies the signature with the stored public key, that the challenge is its own, that the origin is its own, and the authenticator flags (presence and, if required, user verification). The signature counter is only checked if it is not 0: synced passkeys from Apple, Google and Microsoft always send 0, so counter-based clone detection only works with physical keys. Then it creates the session.

**Why it resists phishing:** the browser includes the real origin (`https://example.com`) in what gets signed, and the authenticator only uses the key bound to that `rp.id`. On a fake site such as `exarnple.com` there is no credential to use, and even if the attacker relays the messages, the signature would carry the wrong origin. There is nothing the user can type into the fake site by mistake.

**Exactly what is signed:** `signature = Sign(private_key, authenticatorData || SHA-256(clientDataJSON))`.

```
clientDataJSON (built by the browser, not the page):
  {"type":"webauthn.get", "challenge":"<base64url>", "origin":"https://example.com", "crossOrigin":false}

authenticatorData (built by the authenticator):
  rpIdHash   32 bytes   SHA-256("example.com")
  flags       1 byte    UP (presence), UV (verification), BE/BS (backup eligible / backed up), AT, ED
  signCount   4 bytes   counter (0 on synced passkeys)
  [credential data and extensions, at registration]
```

The server checks, in this order: `type`, that the `challenge` is the one it generated (and not used before), the `origin`, that `rpIdHash` is the SHA-256 of its `rp.id`, the UP flag, the UV flag if its policy requires it, and the signature with the stored public key. Algorithms are identified by COSE codes: ES256 (-7), EdDSA (-8) and RS256 (-257). The BE and BS flags say whether the credential can be synced and whether it already is, which lets you, for example, require physical keys for administrator accounts.

### Attacks and defences

| Attack | What it is | Defence |
| --- | --- | --- |
| Brute force and *credential stuffing* | Trying passwords or pairs leaked from other sites | Attempt limits, MFA, checking breached passwords, passkeys |
| Phishing | Fake site capturing password and OTP code | WebAuthn/passkeys; TOTP and SMS do not stop it |
| Database theft | Reading stored hashes, secrets or tokens | Salted Argon2id, hashed API keys and refresh tokens, encrypted TOTP secrets |
| XSS | Injected script that steals or uses tokens | Output escaping, Content-Security-Policy, `HttpOnly` cookies, no tokens in `localStorage` |
| CSRF | Another site triggers requests with your cookies | `SameSite`, anti-CSRF token, `Origin` check |
| Session fixation | Victim uses an ID the attacker knows | Regenerate the session ID on authentication |
| Cookie or token theft | Copying the bearer credential | HTTPS and HSTS, short lifetimes, refresh token rotation, mTLS or DPoP |
| JWT tampering | `alg: none`, algorithm confusion, malicious `kid` | Fixed algorithm, validate `iss`, `aud` and `exp`, maintained library |
| OAuth code theft | Intercepting the redirect carrying the `code` | PKCE, exact `redirect_uri`, `state` |
| Open redirect | Redirecting after login to an attacker's domain | Allow-list of redirect targets |
| User enumeration | Different messages or timing when the user exists | Same message and same response time in every case |
| MFA fatigue | Flooding the user with push notifications | *Number matching*, request limits |

### Which mechanism to use when

| Scenario | Recommendation |
| --- | --- |
| Classic server-rendered web application | Session with a `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax` cookie |
| SPA (React, Vue...) with its own backend | BFF pattern: session cookie in the browser and tokens only in the backend |
| Mobile or desktop app | OAuth authorization code + PKCE with the system browser; tokens in the secure store |
| "Sign in with..." or SSO | OpenID Connect; SAML if the corporate directory requires it |
| Public API for third parties | OAuth 2.0 (client credentials or authorization code) or scoped API keys |
| Internal microservices | mTLS, or client credentials with short-lived JWTs |
| Scripts and internal tools | API key or HTTP Basic, always over HTTPS |
| User login in general | Passkeys as the goal; if there is a password, Argon2id and a second factor |

## Common attacks and how to prevent them

Today almost no attack breaks TLS cryptography. The ones that work go around encryption: they trick the user into handing over credentials, steal the already-authenticated session, or exploit a server that does not properly check who may do what. This section walks through the most common attacks layer by layer, with how they work, real cases and the concrete configuration to prevent them.

| Layer | Most common attacks | Main defence |
| --- | --- | --- |
| Transport | SSL stripping, fraudulent certificates, old versions and ciphers | HSTS with preload, TLS 1.2+ with AEAD, CAA and Certificate Transparency monitoring |
| Credentials | Credential stuffing, proxy phishing (AiTM), MFA fatigue, SIM swapping | Passkeys, attempt limits, breached passwords blocked |
| Session | Cookie theft by malware, XSS, CSRF, clickjacking | `HttpOnly` + `SameSite` cookies, CSP, device-bound sessions |
| Tokens and OAuth | JWT algorithm confusion, token leaks, open redirects, consent phishing | Strict validation, PKCE, exact `redirect_uri`, short lifetimes |
| Server | IDOR, SSRF, SQL injection | Authorization on every request, destination allow-lists, parameterized queries |

The OWASP Top 10:2025, the usual reference in web security, still ranks **broken access control** first (A01), which now includes SSRF. It is followed by security misconfiguration (A02) and software supply chain failures (A03). Authentication failures are A07 and cryptographic failures A04.

### Transport attacks

#### SSL stripping

**How it works:** the user types `example.com` and the browser starts with `http://`. An attacker on the same network (public Wi-Fi, a compromised router) intercepts that first plaintext request, talks HTTPS to the real server and serves the site to the user over HTTP. The user sees the usual page, without the padlock, and sends their password in the clear to the attacker.

**How to prevent it:**

- Redirect all HTTP to HTTPS with a 301.
- Send **HSTS**: the browser remembers that this domain is only used over HTTPS and does not try HTTP again for `max-age` seconds.

  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```
- To protect the **first** visit too, submit the domain to the HSTS preload list (hstspreload.org), which ships inside browsers. Requirements: `max-age` of at least one year, `includeSubDomains`, the `preload` directive and every subdomain on HTTPS. Getting off the list takes months, so be sure before submitting.

#### Fraudulent certificates and compromised CAs

**How it works:** if an attacker obtains a valid certificate for your domain, through a compromised CA, a flaw in its validation or a hijacked DNS, they can impersonate the site without any browser warning. It has happened: DigiNotar (2011) issued fake Google certificates used to spy on users in Iran, and the CA went bankrupt.

**How to prevent it:**

- **DNS CAA record** (RFC 8659): states which CAs may issue certificates for your domain. CAs are required to honour it.

  ```
  example.com.  CAA 0 issue "letsencrypt.org"
  example.com.  CAA 0 issuewild ";"
  example.com.  CAA 0 iodef "mailto:security@example.com"
  ```
- **Monitor Certificate Transparency:** since every public certificate must appear in the CT logs, you can get alerts for any certificate issued for your domain (crt.sh, Cert Spotter, Cloudflare's or Facebook's monitor).
- **DNSSEC and registrar lock:** if the attacker controls your DNS, they can pass any CA's domain validation. Protect the registrar account with strong MFA and enable transfer lock.
- **No *certificate pinning* on websites:** pinning specific keys in the client was abandoned in browsers (HPKP) because it locked out entire sites by mistake. It only makes sense in your own apps, and carefully now that certificates last only weeks.

#### Historical attacks on TLS and SSL

Almost all of these are fixed in TLS 1.3, but they reappear on servers that keep old configurations for compatibility:

| Attack | Year | What it exploited | If still a risk, what prevents it |
| --- | --- | --- | --- |
| BEAST | 2011 | Predictable CBC IV in TLS 1.0 | Disable TLS 1.0 and 1.1 |
| CRIME | 2012 | TLS-level compression: the size leaks secrets | TLS compression disabled (removed in 1.3) |
| BREACH | 2013 | The same idea with HTTP compression (gzip) | Do not compress responses mixing secrets and user data; mask CSRF tokens on every response |
| Lucky13 | 2013 | Timing differences when checking the MAC in CBC | AEAD suites only |
| Heartbleed (CVE-2014-0160) | 2014 | Bug in OpenSSL 1.0.1-1.0.1f that leaked 64 KB of server memory, including private keys | Keep OpenSSL up to date; after such a bug, revoke and reissue certificates |
| POODLE (CVE-2014-3566) | 2014 | CBC padding in SSL 3.0 | SSL 3.0 disabled |
| FREAK and Logjam | 2015 | 512-bit "export" suites (RSA and DH) | No export suites; DH of at least 2048 bits |
| Sweet32 | 2016 | Collisions in 64-bit block ciphers (3DES) | No 3DES |
| ROBOT | 2017 | Bleichenbacher oracle in RSA key exchange | No RSA key exchange; ECDHE only |

**How to prevent them all at once:** offer only TLS 1.2 (with ECDHE and AEAD) and TLS 1.3, keep the TLS library up to date and check with `testssl.sh` or the SSL Labs test after every configuration change.

### Credential theft and abuse

#### Credential stuffing and password spraying

**How they work:** in *credential stuffing*, the attacker tries username/password pairs leaked from other sites, because many people reuse passwords; in *password spraying*, they try a few common passwords (`Summer2026!`) against many accounts, to avoid triggering per-account lockout. Both use botnets with thousands of residential IPs, so limiting by IP is not enough.

**How to detect it:** many login failures spread across many accounts, an abnormally low success rate, spikes from new IP ranges or repeated user agents.

**How to prevent it:**

- Limit attempts **per account and per IP**, with increasing delays rather than permanent lockouts, which an attacker would use to lock other people out.
- Reject passwords that appear in breaches. The Pwned Passwords service lets you check without revealing the password: you send only the first 5 hex characters of its SHA-1 and receive the list of matching suffixes (*k-anonymity*).

  ```bash
  h=$(printf '%s' 'Summer2026!' | sha1sum | tr a-f A-F | cut -c1-40)
  curl -s "https://api.pwnedpasswords.com/range/${h:0:5}" | grep "${h:5}"
  ```
- MFA or, better, passkeys, which remove the problem because there is no password to reuse.
- A CAPTCHA or proof-of-work challenge only when the risk is high, not on every login.

#### Adversary-in-the-middle (AiTM) phishing

This is the current form of phishing, and the reason TOTP, SMS and push notifications are no longer enough. Instead of a static copy of the site, the attacker places a **reverse proxy** between the victim and the real site (with public tools such as Evilginx). The victim sees the genuine site, completes the login with their second factor, and the proxy keeps the session cookie the real site returns. In 2022 Microsoft documented an AiTM campaign against more than 10,000 organizations.

&#91;embedded content: AiTM phishing · the proxy captures the session after the second factor\]

**How to prevent it:**

- **Passkeys or FIDO2 keys:** the only complete defence. The browser signs the real origin (`https://login-example.com`), the authenticator has no credential for that domain and, even if the proxy relayed the signature, the server would see an origin that is not its own.
- **Device-bound sessions:** with DBSC or bound tokens, a stolen cookie does not work from another machine.
- **Conditional access:** require the login to come from managed devices or known locations, and alert on sessions that change country or device fingerprint shortly after login.
- **Recognisable domains:** always use the same login domain and teach users to check it, although that alone is not enough.

#### MFA fatigue and SIM swapping

- **MFA fatigue:** with the password already stolen, the attacker fires push approvals non-stop, often at night, until the user accepts one to make them stop. That is how the attacker got into Uber in 2022, combined with a message pretending to come from IT support. Prevent it with *number matching* (the user types the number shown on screen), showing the request's location, limiting requests and alerting the security team when someone rejects them.
- **SIM swapping:** the attacker convinces the carrier to issue them a copy of the victim's SIM and receives their SMS. There is no technical defence inside the application: the fix is not to use SMS as a factor for important accounts and not to allow account recovery with SMS alone.

#### Password recovery

It is the back door of every login, and often the weakest:

- **Link token:** at least 128 random bits, single-use, short expiry (15-60 minutes) and stored hashed, like a password.
- **Host header poisoning:** if the server builds the email link from the request's `Host` header, an attacker requests a reset with `Host: attacker.com` and the victim receives a genuine email whose link sends their token to the attacker. Always build the link from the configured base URL.
- **Always the same response:** "if the account exists, you will receive an email", so as not to reveal which emails are registered.
- **After the change:** end all sessions, revoke refresh tokens and notify the user by email.

### Session hijacking

#### Cookie theft by malware (infostealers)

**How it works:** *infostealer* malware (RedLine, Lumma and similar, usually arriving with pirated software or fake extensions) copies the cookies from the browser profile and sells them. The buyer imports them into their browser and enters the already-authenticated account, with no password or second factor (*pass-the-cookie*). `HttpOnly` does not help here: it protects against JavaScript, not against a program reading the disk.

**How to prevent it:**

- **Device Bound Session Credentials (DBSC):** the browser generates a key in the machine's TPM, which cannot be exported, and the server issues very short-lived cookies that are only renewed if the browser proves it holds that key. A stolen cookie expires within minutes and cannot be renewed from another machine. Chrome has offered it generally since version 146 on Windows (April 2026), with macOS on the way. The server has to implement the registration and refresh endpoints.
- **Risk signals:** invalidate the session if the IP, country, operating system or client TLS fingerprint changes abruptly, and ask for login again before sensitive actions (changing the email, adding a payment method, creating API keys).
- **Short lifetimes and revocation:** idle and absolute timeouts, and a "log out all sessions" button that really deletes the sessions on the server.

#### XSS (Cross-Site Scripting)

**How it works:** the application inserts user data into the page without escaping it, for example a comment containing `<script>`. The script runs with your site's origin, so it can read `localStorage`, call your API with the user's cookies or change the login form to send the password elsewhere.

**How to prevent it:**

- **Context-aware escaping:** use the framework's template engine (Jinja2, React, Razor), which escapes by default, and do not bypass that escaping (`|safe`, `dangerouslySetInnerHTML`, `innerHTML`) with user data.
- **Content-Security-Policy with nonces:** the browser only runs scripts carrying that response's random nonce. An injected script does not know it.

  ```
  Content-Security-Policy: default-src 'self'; script-src 'nonce-R4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
  ```
- **Do not store tokens where JavaScript can read them**, and use `HttpOnly` session cookies.
- **Trusted Types** (in Chromium browsers) blocks assigning strings to `innerHTML` and similar sinks unless they pass through a sanitizing function.

#### CSRF

Covered in the sessions section. Summary of defences, most important first: `SameSite=Lax` or `Strict` on the session cookie, rejecting state-changing requests with a foreign `Origin` or `Sec-Fetch-Site: cross-site`, and an anti-CSRF token in forms. Never change state with GET requests.

#### Clickjacking

**How it works:** a malicious site loads yours in a transparent iframe on top of a decoy button. The user thinks they are clicking "watch video" but are actually clicking "authorize application" or "delete account" on your site, with their session.

**How to prevent it:** stop the site from being loaded in other sites' iframes with `Content-Security-Policy: frame-ancestors 'self'` (or `'none'`). The older `X-Frame-Options: DENY` header is kept for old browsers. OAuth consent and payment screens should always send it.

### Token and OAuth attacks

#### JWT algorithm confusion

**How it works:** the API signs with RS256 and verifies with its public key, which is public by definition. The attacker creates a token with `"alg": "HS256"` and signs it with HMAC using that **public key** as the secret. If the server lets the header choose the algorithm, it will verify an HMAC with the same public key and the forged token will be valid. The `"alg": "none"` variant is even simpler: a token with no signature.

```python
# VULNERABLE: the token decides how it is verified
alg = jwt.get_unverified_header(token)["alg"]
claims = jwt.decode(token, PUBLIC_KEY_PEM, algorithms=[alg])

# CORRECT: the server fixes the algorithm, and issuer and audience are validated
claims = jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"],
                    audience="https://api.example.com", issuer="https://auth.example.com")
```

Tested with PyJWT 2.15: given an HS256 token signed with the public key, the correct version rejects it with `InvalidAlgorithmError`. PyJWT 2.x also has a second barrier: it refuses to use a PEM key as an HMAC secret (`InvalidKeyError`). Other libraries, and older versions, do not, so the real defence is fixing the algorithm.

**Other common JWT flaws:** weak HS256 secrets that hashcat cracks from a single token, not checking `exp` or `aud`, and accepting keys from the `jku`, `x5u` or `jwk` headers.

#### Token leaks

A leaked *bearer* token is a stolen session. The most common leaks:

- **In the URL:** `?access_token=...` ends up in history, in server and proxy logs, and in the `Referer` header sent to other sites. Tokens always go in the `Authorization` header. If a flow forces them into the URL, add `Referrer-Policy: no-referrer`.
- **In logs:** logging full headers, request bodies or URLs containing tokens. Filter `Authorization`, `Cookie` and parameters such as `code`, `token` or `password` before writing the log.
- **In code:** API keys in repositories, Docker images or mobile apps. Prevent it with secret scanners in CI and in the repository (GitHub Secret Scanning, gitleaks) and with immediate rotation when one shows up.

#### Open redirects and redirect\_uri manipulation

**How it works:** your site has `/logout?next=https://...` and redirects anywhere. The attacker uses it so a phishing link starts with your domain. And if the authorization server accepts `redirect_uri` by prefix or with wildcards, the attacker registers or finds a valid URL that ends up sending the authorization code to their server.

**How to prevent it:** redirect only to relative paths or to an allow-list of destinations; in OAuth, **exact** `redirect_uri` matching against the registered ones (RFC 9700), and PKCE, which makes a stolen code useless.

#### Consent phishing (illicit consent grant)

**How it works:** the attacker registers an OAuth application with a believable name ("PDF Viewer") in Microsoft 365 or Google Workspace and sends the victim the provider's **legitimate** authorization link. The victim signs in on the real site, with their MFA, and grants permissions such as `Mail.Read` or `offline_access`. The attacker gets a refresh token that survives password changes.

**How to prevent it:** stop users from granting permissions to unverified applications (or require administrator approval), periodically review the authorized applications in the tenant and revoke their tokens if they look suspicious.

### Server-side attacks

#### Broken access control and IDOR

OWASP's number one category. The user is properly authenticated, but the server does not check whether **that** user may access **that** resource. The typical case is IDOR (*Insecure Direct Object Reference*): changing `/api/invoices/1041` to `/api/invoices/1042` and seeing another customer's invoice.

```python
# VULNERABLE: checks there is a session, but not whose invoice it is
@app.get("/api/invoices/<int:id>")
@require_session
def invoice(id):
    return jsonify(db.invoice(id))

# CORRECT: the query is limited to the authenticated user's resources
@app.get("/api/invoices/<int:id>")
@require_session
def invoice(id):
    inv = db.invoice(id, owner=g.user)
    if inv is None:
        return jsonify(error="not found"), 404   # 404, not 403: does not reveal it exists
    return jsonify(inv)
```

**How to prevent it:** deny by default, check authorization on the server on **every** request (never rely on a button being hidden in the UI), filter queries by owner or tenant, and add automated tests that try to access one user's resources as another. Random identifiers (UUIDs) make guessing harder, but do not replace the check.

#### SSRF (Server-Side Request Forgery)

**How it works:** the application fetches a URL supplied by the user (a profile picture, a link preview, a webhook). The attacker supplies an internal URL: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, the cloud metadata service, which returns the server's temporary credentials. That is how the Capital One breach happened in 2019, with data on about 100 million customers. Other common targets are admin panels on `localhost`, Redis, or services on the internal network.

**How to prevent it:**

- **Allow-list** of domains or, if that is not possible, resolve the name and reject private, loopback and link-local (`169.254.0.0/16`) addresses, `fd00::/8` and similar.
- **Validate the IP actually connected to**, not just the one resolved earlier: otherwise *DNS rebinding* returns a public IP at validation time and an internal one at connection time. Also disable automatic redirects or validate every hop.
- **In the cloud, IMDSv2** (AWS) or its equivalent: the metadata service requires a token obtained with a PUT and a hop limit of 1, which blocks almost all simple SSRF.
- Make the fetches from an isolated service with no access to the internal network, and give the server's credentials least privilege.

#### SQL injection at login

**How it works:** the query is built by pasting in user text. With the username `x' OR '1'='1' --`, the condition is always true and the query returns the first user in the table, usually the administrator.

```python
username = "x' OR '1'='1' --"

# VULNERABLE: concatenation
db.execute(f"SELECT username FROM users WHERE username = '{username}'").fetchone()
# -> ('admin',)

# CORRECT: parameterized query; the data is never interpreted as SQL
db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
# -> None
```

Both results are real, run with SQLite. **How to prevent it:** always use parameterized queries or an ORM, never build SQL from strings; give the application's database account least privilege; and at login, fetch the user by name and verify the hash in code, never with `WHERE password = ...`.

### Hardening checklist

#### nginx configuration

This configuration combines the transport and browser defences from this section. It was tested with nginx 1.24 (the one in Ubuntu 24.04): `nginx -t` accepts it, the redirect goes to the configured domain and all six headers arrive even on error responses.

```nginx
server {
    listen 80;
    server_name example.com;
    # Fixed domain: the URL is not built from the client's Host header
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl http2;        # nginx 1.25.1 or later: "listen 443 ssl;" and "http2 on;"
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;     # in TLS 1.2, a ticket key that never rotates breaks forward secrecy
    server_tokens off;           # do not advertise the nginx version

    # "always": also on error responses (4xx, 5xx)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
```

Two nginx caveats: `add_header` inside a `location` block **overrides** all headers inherited from `server`, so you must repeat them or move them to a shared file with `include`. And the example CSP is strict: with inline scripts or styles, the site will break until you add nonces. Start with `Content-Security-Policy-Report-Only` to see what would break.

#### Tasks

**Transport**

- [ ] TLS 1.2 and 1.3 only; in 1.2, ECDHE with AEAD only
- [ ] HTTP redirects to HTTPS and HSTS is sent with `max-age` of at least one year
- [ ] Domain on the HSTS preload list (if every subdomain uses HTTPS)
- [ ] DNS CAA record with the authorized CAs
- [ ] Certificate Transparency alerts for the domain
- [ ] Automatic certificate renewal with ACME, ready for 47-day validity
- [ ] `testssl.sh` or SSL Labs with no warnings after every change

**Credentials and session**

- [ ] Passwords with Argon2id (or bcrypt) and OWASP parameters
- [ ] Attempt limits per account and per IP
- [ ] Breached passwords rejected at sign-up and on change
- [ ] Passkeys available; mandatory for administrators
- [ ] No SMS as the only second factor; *number matching* for push
- [ ] `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` session cookie, regenerated on authentication
- [ ] Idle and absolute timeouts; logout that deletes the session on the server
- [ ] Password recovery with a single-use random token, fixed base URL and session termination

**Tokens and OAuth**

- [ ] JWT algorithm fixed on the server; `iss`, `aud` and `exp` validated
- [ ] Access tokens of 15 minutes or less; rotating refresh tokens with reuse detection
- [ ] Tokens kept out of URLs and logs; secret scanner on the repository
- [ ] PKCE S256 and exact `redirect_uri` on every OAuth client
- [ ] Third-party app consent restricted in the tenant

**Application**

- [ ] Authorization checked on every endpoint, with cross-user access tests
- [ ] Parameterized queries throughout the code
- [ ] URL fetches with an allow-list and no internal network access; IMDSv2 in the cloud
- [ ] CSP with nonces, `frame-ancestors` and the other security headers
- [ ] Authentication logs (successes, failures, MFA changes) with alerts, without sensitive data

## References

Specifications this document is based on, and sources for the facts that change over time (checked in November 2026).

**TLS and certificates**

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) · [RFC 9001 — TLS in QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 5746 — renegotiation\_info](https://www.rfc-editor.org/rfc/rfc5746) · [RFC 7627 — Extended Master Secret](https://www.rfc-editor.org/rfc/rfc7627) · [RFC 7366 — Encrypt-then-MAC](https://www.rfc-editor.org/rfc/rfc7366) · [RFC 7905 — ChaCha20-Poly1305 in TLS](https://www.rfc-editor.org/rfc/rfc7905)
- [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/info/rfc9849) (November 2025) · [RFC 9266 — tls-exporter channel binding](https://www.rfc-editor.org/rfc/rfc9266)
- [RFC 5280 — X.509 certificate profile](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 9525 — service identity verification](https://www.rfc-editor.org/rfc/rfc9525) · [RFC 8555 — ACME](https://www.rfc-editor.org/rfc/rfc8555) · [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- Hybrid post-quantum key exchange: [X25519MLKEM768 support list in Cloudflare's documentation](https://github.com/cloudflare/cloudflare-docs/pull/26233.diff)
- Certificate validity: [CA/Browser Forum ballot SC-081v3, summarized by DNSimple](https://support.dnsimple.com/articles/announcement-ssl-certificate-validity-changes/)
- OCSP: [Let's Encrypt, "Ending OCSP Support in 2025"](https://letsencrypt.org/2024/12/05/ending-ocsp/) and [shutdown announcement](https://community.letsencrypt.org/t/ending-ocsp-support-in-2025/229786)

**Web authentication**

- [RFC 7617 — HTTP Basic](https://www.rfc-editor.org/rfc/rfc7617) · [RFC 7616 — HTTP Digest](https://www.rfc-editor.org/rfc/rfc7616) · [RFC 6265 — cookies](https://www.rfc-editor.org/rfc/rfc6265)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106) · [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519) · [RFC 8725 — JWT best practices](https://www.rfc-editor.org/rfc/rfc8725) · [RFC 9068 — JWT access tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) · [RFC 6750 — Bearer](https://www.rfc-editor.org/rfc/rfc6750) · [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636) · [RFC 9700 — OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html) · [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [RFC 9207 — iss parameter](https://www.rfc-editor.org/rfc/rfc9207) · [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126) · [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449) · [RFC 8705 — OAuth with mTLS](https://www.rfc-editor.org/rfc/rfc8705) · [RFC 8628 — device flow](https://www.rfc-editor.org/rfc/rfc8628)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 4226 — HOTP](https://www.rfc-editor.org/rfc/rfc4226) · [RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [W3C Web Authentication](https://www.w3.org/TR/webauthn-2/) · signature counter on passkeys: [MojoAuth, "signCount Is Dead"](https://mojoauth.com/blog/signcount-is-dead-why-passkey-clone-detection-doesnt-work-anymore)

**Attacks and defences**

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) · [RFC 8659 — DNS CAA records](https://www.rfc-editor.org/rfc/rfc8659) · [RFC 6797 — HSTS](https://www.rfc-editor.org/rfc/rfc6797) · [HSTS preload list](https://hstspreload.org/)
- [Google, "Protecting Cookies with Device Bound Session Credentials"](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/) (April 2026)
- [Pwned Passwords — range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

## Appendix A: abbreviations

| Abbreviation | Stands for | What it is |
| --- | --- | --- |
| 0-RTT | Zero Round-Trip Time | Sending data in the first flight, without waiting for a reply |
| 3DES | Triple Data Encryption Standard | Old block cipher, removed in TLS 1.3 |
| AAD | Additional Authenticated Data | Data that is authenticated but not encrypted (the record header) |
| ACME | Automatic Certificate Management Environment | Protocol for requesting and renewing certificates automatically (RFC 8555) |
| AEAD | Authenticated Encryption with Associated Data | Encryption that protects confidentiality and integrity at once |
| AES | Advanced Encryption Standard | Standard symmetric block cipher |
| ALPN | Application-Layer Protocol Negotiation | Extension that negotiates the application protocol (h2, http/1.1) |
| BFF | Backend for Frontend | Application backend that holds the tokens; the browser only has a session cookie |
| CA | Certificate Authority | Authority that signs certificates |
| CBC | Cipher Block Chaining | Block cipher mode, vulnerable in TLS (Lucky13, POODLE) |
| CCM | Counter with CBC-MAC | AES AEAD mode, used mainly on small devices |
| CCS | ChangeCipherSpec | TLS 1.2 record meaning "from here on, I encrypt" |
| ChaCha20-Poly1305 | ChaCha20 cipher + Poly1305 MAC | Fast AEAD without hardware acceleration |
| CRL | Certificate Revocation List | Signed list of revoked certificates published by the CA |
| CSRF | Cross-Site Request Forgery | Another site makes the browser send requests with your cookies |
| CT | Certificate Transparency | Public logs of every issued certificate |
| DH / DHE | Diffie-Hellman / Diffie-Hellman Ephemeral | Key agreement; the E means single-use keys |
| DNS | Domain Name System | Resolves domain names to IP addresses |
| DoH / DoT | DNS over HTTPS / DNS over TLS | Encrypted DNS |
| DPoP | Demonstrating Proof of Possession | Binds an OAuth token to a client key (RFC 9449) |
| ECDHE | Elliptic Curve Diffie-Hellman Ephemeral | Diffie-Hellman over elliptic curves with ephemeral keys |
| ECH | Encrypted Client Hello | Extension that encrypts the ClientHello, including the SNI |
| GCM | Galois/Counter Mode | AES AEAD mode |
| HKDF | HMAC-based Key Derivation Function | TLS 1.3 key derivation function (Extract + Expand) |
| HMAC | Hash-based Message Authentication Code | MAC built on a hash function |
| HPKE | Hybrid Public Key Encryption | Hybrid public-key encryption used by ECH (RFC 9180) |
| HRR | HelloRetryRequest | TLS 1.3 reply asking for a different key\_share |
| HSM | Hardware Security Module | Device that stores keys and signs without letting them out |
| HSTS | HTTP Strict Transport Security | Header that forces the browser to always use HTTPS |
| HTTP / HTTPS | Hypertext Transfer Protocol (Secure) | The web protocol; HTTPS is HTTP over TLS |
| IdP | Identity Provider | Provider that authenticates the user in SSO (OIDC or SAML) |
| IV | Initialization Vector | Initial value that makes each encryption unique |
| JWKS | JSON Web Key Set | Set of public keys published by a JWT issuer |
| JWT | JSON Web Token | Signed token with header, payload and signature in base64url (RFC 7519) |
| KEM | Key Encapsulation Mechanism | Mechanism for agreeing on a secret by encrypting it with a public key |
| MAC | Message Authentication Code | Code that proves a message's integrity and origin |
| MFA | Multi-Factor Authentication | Authentication with at least two different factors |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism | Post-quantum key exchange (formerly Kyber) |
| mTLS | Mutual TLS | TLS in which the client also presents a certificate |
| OAuth | Open Authorization | Delegated authorization protocol (RFC 6749) |
| OCSP | Online Certificate Status Protocol | Query to check whether a certificate is revoked |
| OIDC | OpenID Connect | Identity layer on top of OAuth 2.0; adds the ID token |
| PAR | Pushed Authorization Requests | Sending the /authorize parameters over the back channel (RFC 9126) |
| PKCE | Proof Key for Code Exchange | Protects the OAuth authorization code (RFC 7636) |
| PKCS#1 | Public-Key Cryptography Standards #1 | The RSA standard; its v1.5 signature is not valid for CertificateVerify in 1.3, though it is for signing certificates |
| PKI | Public Key Infrastructure | CAs, certificates and policies for managing public keys |
| POODLE | Padding Oracle On Downgraded Legacy Encryption | Attack on CBC in SSL 3.0 |
| PRF | Pseudo-Random Function | TLS 1.2 key derivation function |
| PSK | Pre-Shared Key | Previously shared key; in 1.3, the one derived from a ticket |
| QUIC | QUIC (a name, not an acronym) | Transport over UDP with built-in TLS 1.3; the basis of HTTP/3 |
| RC4 | Rivest Cipher 4 | Broken stream cipher, prohibited in TLS |
| RFC | Request for Comments | Documents that define Internet standards |
| RSA | Rivest-Shamir-Adleman | Public-key algorithm for signatures and encryption |
| RSA-PSS | RSA Probabilistic Signature Scheme | RSA signature scheme mandatory for CertificateVerify in TLS 1.3 |
| RTT | Round-Trip Time | One round trip between client and server |
| SAML | Security Assertion Markup Language | XML standard for corporate single sign-on |
| SAN | Subject Alternative Name | Certificate field listing the domains it covers |
| SCT | Signed Certificate Timestamp | Signed proof that a certificate is in a CT log |
| SHA-256 | Secure Hash Algorithm, 256 bits | Hash function used in key derivation and signatures |
| SNI | Server Name Indication | Extension carrying the domain the client connects to |
| SP | Service Provider | In SAML, the application that trusts the IdP |
| SSL | Secure Sockets Layer | TLS's obsolete predecessor |
| SSO | Single Sign-On | Sign in once and access several applications |
| SVCB / HTTPS RR | Service Binding | DNS records that publish service parameters, such as the ECH key |
| TCP / UDP | Transmission Control Protocol / User Datagram Protocol | Transport protocols over IP |
| TLS | Transport Layer Security | The encryption protocol this document is about |
| TOTP | Time-based One-Time Password | One-time code based on the current time (RFC 6238) |
| WebAuthn | Web Authentication | W3C API for authenticating with public keys; the basis of passkeys |
| X.509 | ITU-T X.509 standard | Format of public-key certificates |
| X25519 | Curve25519 for Diffie-Hellman | Most used ECDHE group in TLS 1.3 |
| XSS | Cross-Site Scripting | Injecting JavaScript into a page to steal data or act as the user |

## Appendix B: C client and server with OpenSSL

An echo server and a client that connect with SSL 3.0, TLS 1.2 or TLS 1.3, depending on the argument they are given. Both set the minimum and maximum version to the same value, so they only accept that protocol. Tested with OpenSSL 3.0.13 on Linux.

### Requirements and certificates

You need `gcc` and the OpenSSL headers (`libssl-dev` on Debian/Ubuntu). The client verifies the server certificate, so first create a test CA and a certificate for `localhost` signed by it:

```bash
sudo apt install build-essential libssl-dev

# Test CA (keyUsage and basicConstraints: required by strict clients such as Python 3.13)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 365 -subj "/CN=My Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server certificate for localhost, signed by the CA
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"
cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -extfile san.ext
```

### server.c

```c
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
```

### client.c

```c
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
```

### Building and testing TLS 1.2 and TLS 1.3

```bash
gcc -Wall -o server server.c -lssl -lcrypto
gcc -Wall -o client client.c -lssl -lcrypto

# Terminal 1
./server 4433 tls1.3 server.pem server.key

# Terminal 2
./client localhost 4433 tls1.3 ca.pem "Hello from tls1.3"
```

Actual output from the tests:

```
Connected with TLSv1.3, cipher TLS_AES_256_GCM_SHA384
Server certificate: /CN=localhost
Reply: Echo (TLSv1.3): Hello from tls1.3

Connected with TLSv1.2, cipher ECDHE-RSA-AES256-GCM-SHA384
Server certificate: /CN=localhost
Reply: Echo (TLSv1.2): Hello from tls1.2
```

The cipher name already shows the difference between versions: in TLS 1.3 the suite only names the AEAD and the hash (`TLS_AES_256_GCM_SHA384`), whereas in TLS 1.2 it also includes the key exchange and authentication (`ECDHE-RSA-...`).

If client and server ask for different versions (server on `tls1.3`, client on `tls1.2`), the handshake fails with the `protocol_version` alert (number 70):

```
Handshake failed (verification: ok)
...:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:...:SSL alert number 70
```

### SSL 3.0: needs a purpose-built OpenSSL

The OpenSSL shipped by Debian, Ubuntu and most distributions is built without SSL 3.0. With it, `ssl3` mode fails on both sides with `no protocols available`. To try it you need to build OpenSSL with `enable-ssl3` in a separate directory, without touching the system one:

```bash
git clone --depth 1 --branch openssl-3.0.13 https://github.com/openssl/openssl.git
cd openssl
./Configure enable-ssl3 enable-ssl3-method no-tests --prefix=$HOME/ossl-ssl3 --libdir=lib
make -j$(nproc) && make install_sw
cd ..

O=$HOME/ossl-ssl3
gcc -Wall -I$O/include -o server3 server.c -L$O/lib -Wl,-rpath,$O/lib -lssl -lcrypto
gcc -Wall -I$O/include -o client3 client.c -L$O/lib -Wl,-rpath,$O/lib -lssl -lcrypto

./server3 4433 ssl3 server.pem server.key            # terminal 1
./client3 localhost 4433 ssl3 ca.pem "Hello from ssl3" # terminal 2
```

Actual output with that build:

```
Connected with SSLv3, cipher AES256-SHA
Server certificate: /CN=localhost
Reply: Echo (SSLv3): Hello from ssl3
```

The negotiated cipher, `AES256-SHA`, uses static RSA key exchange, CBC and a SHA-1 MAC: no forward secrecy and vulnerable to POODLE. That is why the code lowers the security level to 0 only in that mode. It is useful for studying the protocol in a lab, never for a real service.

### Seeing the handshake in Wireshark

To decrypt these programs' traffic in Wireshark, add this line in `create_context()` of either program, right after `SSL_CTX_new`, and the callback function at the top of the file:

```c
static void log_keys(const SSL *ssl, const char *line)
{
    (void)ssl;
    FILE *f = fopen("/tmp/keys.log", "a");
    if (f) {
        fprintf(f, "%s\n", line);
        fclose(f);
    }
}

/* In create_context(): */
SSL_CTX_set_keylog_callback(ctx, log_keys);
```

Capture with `sudo tcpdump -i lo -w tls.pcap port 4433`, open the file in Wireshark and load `/tmp/keys.log` in Preferences → Protocols → TLS → (Pre)-Master-Secret log filename. You will see every message from this document's diagrams, including the encrypted ones in TLS 1.3.

### Script to test everything: test\_tls.sh

The script runs the whole process in one go: it checks dependencies, creates the certificates, builds, starts server and client in each mode and checks the result is the expected one. Save it next to `server.c` and `client.c`:

```bash
chmod +x test_tls.sh
./test_tls.sh            # TLS 1.3, TLS 1.2, mismatched versions and SSL 3.0 with the system OpenSSL
./test_tls.sh --ssl3     # Also builds an OpenSSL with SSL 3.0 and tests that protocol
./test_tls.sh --clean    # Deletes certificates, binaries and logs
PORT=8443 ./test_tls.sh  # Use another port
```

With `--ssl3` it also needs `git`, `make` and `perl` to build OpenSSL. The first run takes a few minutes; after that it reuses the build in `$HOME/ossl-ssl3`.

| Test | Server | Client | Expected result |
| --- | --- | --- | --- |
| tls1.3 | TLS 1.3 | TLS 1.3 | Connects and returns the echo |
| tls1.2 | TLS 1.2 | TLS 1.2 | Connects and returns the echo |
| mismatch | TLS 1.3 | TLS 1.2 | Fails with the protocol\_version alert |
| ssl3-system | SSL 3.0 | SSL 3.0 | Only reports whether the system OpenSSL supports SSL 3.0 |
| ssl3 (with --ssl3) | SSL 3.0 | SSL 3.0 | Connects with the separately built OpenSSL |

```bash
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
#   OSSL_SSL3=$HOME/ossl-ssl3      Where to install/find the OpenSSL with SSL 3.0
#   OSSL_VERSION=openssl-3.0.13    OpenSSL tag built for SSL 3.0

set -euo pipefail

PORT="${PORT:-4433}"
OSSL_SSL3="${OSSL_SSL3:-$HOME/ossl-ssl3}"
OSSL_VERSION="${OSSL_VERSION:-openssl-3.0.13}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"

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
    rm -f ca.key ca.pem ca.srl server.key server.csr server.pem san.ext \
          server client server3 client3
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
    if [ -f ca.pem ] && [ -f server.pem ] && [ -f server.key ]; then
        ok "already present, reusing them (use --clean to regenerate)"
        return
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
        -days 365 -subj "/CN=My Test CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    ok "test CA created (ca.pem)"

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
    ok "server certificate for localhost (server.pem)"

    openssl verify -CAfile ca.pem server.pem >/dev/null && ok "the chain verifies"
}

# --- 3. Build ---------------------------------------------------------------

build() {
    title "Building against the system OpenSSL"
    gcc -Wall -Wextra -o server server.c -lssl -lcrypto
    gcc -Wall -Wextra -o client client.c -lssl -lcrypto
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

    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o server3 server.c \
        -L"$OSSL_SSL3/lib" -Wl,-rpath,"$OSSL_SSL3/lib" -lssl -lcrypto
    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o client3 client.c \
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

    title "Test: $name (server $psrv, client $pcli)"

    "./$srv" "$PORT" "$psrv" server.pem server.key >"$srv_log" 2>&1 &
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
    timeout 10 "./$cli" localhost "$PORT" "$pcli" ca.pem "Hello from $pcli" \
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

check_dependencies
create_certificates
build
mkdir -p "$LOGS"

run_test tls1.3      server tls1.3 client tls1.3 yes
run_test tls1.2      server tls1.2 client tls1.2 yes
run_test mismatch    server tls1.3 client tls1.2 no
run_test ssl3-system server ssl3   client ssl3   info

if [ "$WITH_SSL3" -eq 1 ]; then
    command -v git >/dev/null || { fail "--ssl3 needs git"; exit 1; }
    build_openssl_ssl3
    run_test ssl3 server3 ssl3 client3 ssl3 yes
fi

title "Summary"
if [ "$FAILURES" -eq 0 ]; then
    ok "all tests behaved as expected (logs in $LOGS)"
else
    fail "$FAILURES test(s) with unexpected results (logs in $LOGS)"
    exit 1
fi
```

Summary of an actual run with `--ssl3` (the script also prints the full client and server output for every test):

```
== Test: tls1.3 (server tls1.3, client tls1.3)
[OK] connection and echo correct
== Test: tls1.2 (server tls1.2, client tls1.2)
[OK] connection and echo correct
== Test: mismatch (server tls1.3, client tls1.2)
[OK] the handshake fails, as expected
== Test: ssl3-system (server ssl3, client ssl3)
[OK] this OpenSSL does not support ssl3 (normal for distributions)
== OpenSSL with SSL 3.0 in /home/juan/ossl-ssl3
[OK] already built, reusing it
[OK] server3 and client3 built against that OpenSSL
== Test: ssl3 (server ssl3, client ssl3)
[OK] connection and echo correct
== Summary
[OK] all tests behaved as expected (logs in ./logs)
```

## Appendix C: authentication code examples

An HTTPS server in Python with Flask that implements what "Web authentication in depth" describes, and a client that checks each mechanism, including the attacks that must fail. A script sets everything up and runs it. Tested with Python 3.13: all 27 checks pass.

| File | Contents |
| --- | --- |
| `auth_utils.py` | Argon2id hashing, TOTP implemented by hand per RFC 6238, PKCE, ES256 JWT access tokens and rotating refresh tokens with reuse detection |
| `auth_server.py` | Password + TOTP login, server-side session with a `__Host-` cookie, CSRF defence via `Origin`, lockout after 5 failures, Bearer-protected API |
| `auth_client.py` | 27 checks: RFC test vectors, login flow, CSRF, `alg=none`, tampered token, refresh token reuse and logout |
| `test_auth.sh` | Creates a virtual environment, installs dependencies, generates certificates, starts the server and runs the client |

This is code for learning: it keeps data in memory and uses Flask's development server. In production, sessions and refresh tokens would live in Redis or a database, signing keys in a secrets store, the server behind Gunicorn and a reverse proxy, and user login probably with an OIDC provider (Keycloak, Entra ID, Auth0).

To try it, put the four files in a folder and run:

```bash
chmod +x test_auth.sh
./test_auth.sh          # Installs dependencies and runs every test
./test_auth.sh --clean  # Deletes the virtual environment, certificates and logs
```

It only needs `python3` with the `venv` module (`sudo apt install python3-venv` on Debian/Ubuntu), `openssl` and `curl`.

### auth\_utils.py

```python
"""
auth_utils.py - Reusable authentication building blocks:
passwords with Argon2id, TOTP (RFC 6238), PKCE (RFC 7636) and
JWT access tokens with rotating refresh tokens.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec


# --------------------------------------------------------------------------
# Passwords: Argon2id with a random salt (the library generates it and stores
# it inside the hash string itself).
# --------------------------------------------------------------------------

_ph = PasswordHasher()                       # Argon2id, RFC 9106 parameters
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash, password: str):
    """Return (valid, new_hash).

    new_hash is not None when the stored parameters are outdated and the
    hash in the database should be updated.
    """
    if stored_hash is None:
        # The user does not exist: compute a hash anyway so the response
        # time does not reveal which users exist.
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        return False, None

    try:
        _ph.verify(stored_hash, password)     # Constant-time comparison
    except (VerifyMismatchError, InvalidHashError):
        return False, None

    new_hash = _ph.hash(password) if _ph.check_needs_rehash(stored_hash) else None
    return True, new_hash


# --------------------------------------------------------------------------
# TOTP (RFC 6238): the same computation authenticator apps perform.
# --------------------------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()   # 160 bits


def totp(secret_b32: str, at=None, step=30, digits=6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F                             # Dynamic truncation
    number = struct.unpack(">I", mac[offset:offset + 4])[0]
    return str((number & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def verify_totp(secret_b32: str, code: str, last_used_step=None,
                window=1, step=30):
    """Return the accepted step number, or None.

    Accepts the current interval and `window` intervals before and after
    (clock skew), and rejects codes from steps already used.
    """
    now = int(time.time() // step)
    for s in range(now - window, now + window + 1):
        if last_used_step is not None and s <= last_used_step:
            continue
        if hmac.compare_digest(totp(secret_b32, s * step, step), code):
            return s
    return None


def totp_uri(secret_b32: str, user: str, issuer: str) -> str:
    """URI shown as a QR code when enrolling the second factor."""
    return f"otpauth://totp/{issuer}:{user}?secret={secret_b32}&issuer={issuer}"


# --------------------------------------------------------------------------
# PKCE (RFC 7636)
# --------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def challenge_s256(code_verifier: str) -> str:
    return b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def generate_pkce():
    """Return (code_verifier, code_challenge)."""
    code_verifier = b64url(secrets.token_bytes(32))     # 43 characters
    return code_verifier, challenge_s256(code_verifier)


# --------------------------------------------------------------------------
# Tokens: JWT access token (ES256, short-lived) + rotating opaque refresh token
# --------------------------------------------------------------------------

class TokenError(Exception):
    pass


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TokenIssuer:
    def __init__(self, issuer, audience, access_ttl=900, refresh_ttl=7 * 86400):
        self.issuer = issuer
        self.audience = audience
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        # Elliptic-curve key pair: sign with the private key and any
        # service can verify with the public one.
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.kid = secrets.token_hex(4)
        # Refresh tokens are stored by their hash, never in the clear.
        self._refresh = {}
        self._revoked_families = set()

    # --- Access token -----------------------------------------------------

    def issue_access(self, sub: str, scope: str) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": sub,
            "aud": self.audience,
            "iat": now,
            "exp": now + self.access_ttl,
            "jti": secrets.token_hex(8),
            "scope": scope,
        }
        return jwt.encode(claims, self.private_key, algorithm="ES256",
                          headers={"kid": self.kid})

    def validate_access(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self.public_key,
                algorithms=["ES256"],          # Fixed: never the one the token names
                audience=self.audience,
                issuer=self.issuer,
                leeway=30,                     # Allowance for clock skew
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as e:
            raise TokenError(f"invalid access token: {e}") from e

    # --- Refresh token ----------------------------------------------------

    def issue_refresh(self, sub: str, scope: str, family=None) -> str:
        token = "rt_" + secrets.token_urlsafe(32)
        self._refresh[_sha256(token)] = {
            "sub": sub,
            "scope": scope,
            "family": family or secrets.token_hex(8),
            "used": False,
            "exp": time.time() + self.refresh_ttl,
        }
        return token

    def refresh(self, refresh_token: str):
        """Exchange a refresh token for a new (access, refresh) pair and invalidate it."""
        data = self._refresh.get(_sha256(refresh_token))
        if (data is None or data["exp"] < time.time()
                or data["family"] in self._revoked_families):
            raise TokenError("invalid refresh token")
        if data["used"]:
            # Reuse: someone has a copy. Revoke the whole family.
            self._revoked_families.add(data["family"])
            raise TokenError("refresh token reused: session revoked")
        data["used"] = True
        return (self.issue_access(data["sub"], data["scope"]),
                self.issue_refresh(data["sub"], data["scope"], data["family"]))

    def revoke(self, refresh_token: str):
        data = self._refresh.get(_sha256(refresh_token))
        if data:
            self._revoked_families.add(data["family"])
```

### auth\_server.py

```python
"""
auth_server.py - Example server with:
  * password login (Argon2id) + TOTP second factor
  * server-side session with a __Host- cookie, regenerated on authentication
  * CSRF defence by checking the Origin header
  * JWT access token + rotating refresh token issued for an API

Usage: python3 auth_server.py   (HTTPS on https://localhost:5443)
For learning only: in-memory data and a single test user.
"""
import os
import secrets
import time
from functools import wraps

from flask import Flask, g, jsonify, request

from auth_utils import (TokenError, TokenIssuer, hash_password,
                        verify_password, verify_totp)

PORT = int(os.environ.get("AUTH_PORT", "5443"))
ORIGIN = f"https://localhost:{PORT}"
COOKIE = "__Host-session"
IDLE_TIMEOUT = 30 * 60         # Idle logout: 30 minutes
MAX_LIFETIME = 12 * 3600       # Absolute logout: 12 hours
MAX_FAILURES, LOCKOUT = 5, 60  # 5 failed attempts -> locked for 60 s

app = Flask(__name__)

# In-memory "database". The password only exists as a hash.
USERS = {
    "juan": {
        "hash": hash_password("correct-horse-battery-staple"),
        "totp": os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP"),
        "last_totp_step": None,
        "scope": "orders:read",
        "failures": 0,
        "locked_until": 0,
    }
}
SESSIONS = {}   # session id -> data
tokens = TokenIssuer(issuer=ORIGIN, audience=ORIGIN + "/api")


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------

def create_session(user, mfa_ok):
    sid = secrets.token_urlsafe(32)          # 256 random bits
    now = time.time()
    SESSIONS[sid] = {"user": user, "mfa_ok": mfa_ok,
                     "created": now, "last_seen": now}
    return sid


def set_cookie(response, sid):
    response.set_cookie(COOKIE, sid, path="/", secure=True, httponly=True,
                        samesite="Lax", max_age=MAX_LIFETIME)
    return response


def current_session():
    sid = request.cookies.get(COOKIE)
    data = SESSIONS.get(sid) if sid else None
    if not data:
        return None, None
    now = time.time()
    if (now - data["last_seen"] > IDLE_TIMEOUT
            or now - data["created"] > MAX_LIFETIME):
        SESSIONS.pop(sid, None)
        return None, None
    data["last_seen"] = now
    return sid, data


def require_session(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        sid, data = current_session()
        if not data or not data["mfa_ok"]:
            return jsonify(error="not authenticated"), 401
        g.sid, g.user = sid, data["user"]
        return f(*args, **kwargs)
    return wrapper


def require_token(scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="missing token"), 401, \
                    {"WWW-Authenticate": 'Bearer realm="api"'}
            try:
                claims = tokens.validate_access(header[7:])
            except TokenError as e:
                return jsonify(error=str(e)), 401, \
                    {"WWW-Authenticate": 'Bearer error="invalid_token"'}
            if scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient scope"), 403
            g.claims = claims
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def csrf_defence():
    # Browsers send Origin on state-changing requests.
    # If it comes from another site, reject it. (SameSite=Lax is the first barrier.)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin is not None and origin != ORIGIN:
            return jsonify(error="origin not allowed"), 403


# --------------------------------------------------------------------------
# Password + TOTP login
# --------------------------------------------------------------------------

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    name, password = data.get("username", ""), data.get("password", "")
    user = USERS.get(name)

    if user and user["locked_until"] > time.time():
        return jsonify(error="too many attempts, wait"), 429

    ok, new_hash = verify_password(user["hash"] if user else None, password)
    if not ok:
        if user:
            user["failures"] += 1
            if user["failures"] >= MAX_FAILURES:
                user["locked_until"] = time.time() + LOCKOUT
                user["failures"] = 0
        # Same message whether or not the user exists
        return jsonify(error="wrong username or password"), 401

    user["failures"] = 0
    if new_hash:
        user["hash"] = new_hash

    # Against session fixation: discard any previous session
    # and create a new identifier.
    old_sid = request.cookies.get(COOKIE)
    SESSIONS.pop(old_sid, None)
    sid = create_session(name, mfa_ok=False)
    return set_cookie(jsonify(mfa_required=True), sid)


@app.post("/login/mfa")
def login_mfa():
    sid, data = current_session()
    if not data:
        return jsonify(error="log in first"), 401
    user = USERS[data["user"]]
    code = (request.get_json(silent=True) or {}).get("code", "")

    step = verify_totp(user["totp"], code, user["last_totp_step"])
    if step is None:
        return jsonify(error="wrong code"), 401
    user["last_totp_step"] = step              # A code cannot be reused

    # Privilege change: new session identifier again.
    SESSIONS.pop(sid, None)
    new_sid = create_session(data["user"], mfa_ok=True)
    return set_cookie(jsonify(ok=True), new_sid)


@app.get("/profile")
@require_session
def profile():
    return jsonify(user=g.user)


@app.post("/logout")
def logout():
    sid = request.cookies.get(COOKIE)
    SESSIONS.pop(sid, None)                    # Deleted on the server
    response = jsonify(ok=True)
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True,
                           samesite="Lax")
    return response


# --------------------------------------------------------------------------
# Token-protected API
# --------------------------------------------------------------------------

@app.post("/api/token")
@require_session
def issue_tokens():
    """Give tokens to an already authenticated user (for example, for a CLI)."""
    scope = USERS[g.user]["scope"]
    return jsonify(access_token=tokens.issue_access(g.user, scope),
                   refresh_token=tokens.issue_refresh(g.user, scope),
                   token_type="Bearer", expires_in=tokens.access_ttl)


@app.post("/api/refresh")
def refresh_tokens():
    refresh = (request.get_json(silent=True) or {}).get("refresh_token", "")
    try:
        access, new_refresh = tokens.refresh(refresh)
    except TokenError as e:
        return jsonify(error=str(e)), 401
    return jsonify(access_token=access, refresh_token=new_refresh,
                   token_type="Bearer", expires_in=tokens.access_ttl)


@app.get("/api/orders")
@require_token("orders:read")
def orders():
    return jsonify(user=g.claims["sub"], orders=[{"id": 1, "total": 42.5}])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT,
            ssl_context=("server.pem", "server.key"))
```

### auth\_client.py

```python
"""
auth_client.py - Exercises every mechanism of the example server
and also checks the auth_utils functions against the RFC test vectors.

Usage: python3 auth_client.py   (with auth_server.py running)
"""
import base64
import json
import os
import sys

import requests

from auth_utils import (challenge_s256, generate_pkce, hash_password, totp,
                        verify_password)

PORT = int(os.environ.get("AUTH_PORT", "5443"))
BASE = f"https://localhost:{PORT}"
TOTP_SECRET = os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
CA = "ca.pem"                       # The server certificate is verified
failures = 0


def check(description, condition, detail=""):
    global failures
    status = "OK    " if condition else "FAIL  "
    if not condition:
        failures += 1
    print(f"[{status}] {description}" + (f"  ({detail})" if detail else ""))


def decode_jwt(token):
    """For display only: does NOT verify the signature."""
    def part(p):
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    header, payload, _ = token.split(".")
    return part(header), part(payload)


# --- 1. Local functions against the RFC test vectors ------------------------

print("== auth_utils functions")
h = hash_password("secret")
check("salted Argon2id hash", h.startswith("$argon2id$"), h[:30] + "...")
check("two hashes of the same password differ", h != hash_password("secret"))
check("accepts the correct password", verify_password(h, "secret")[0])
check("rejects a wrong one", not verify_password(h, "other")[0])

# RFC 6238, appendix B: secret "12345678901234567890", T=59 s -> 94287082
rfc_secret = base64.b32encode(b"12345678901234567890").decode()
check("TOTP matches the RFC 6238 test vector",
      totp(rfc_secret, at=59, digits=8) == "94287082")

# RFC 7636, appendix B
check("PKCE S256 matches the RFC 7636 test vector",
      challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
      == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
verifier, challenge = generate_pkce()
check("PKCE generates a 43-character code_verifier", len(verifier) == 43,
      f"challenge={challenge[:12]}...")

# --- 2. Cookie session + TOTP --------------------------------------------------

print("\n== Cookie session and second factor")
s = requests.Session()
s.verify = CA
s.trust_env = False                 # Ignore proxies and REQUESTS_CA_BUNDLE from the environment
s.headers["Origin"] = BASE          # As a browser on our own site would

r = s.post(f"{BASE}/login", json={"username": "juan", "password": "wrong"})
check("wrong password -> 401", r.status_code == 401)
r = s.post(f"{BASE}/login", json={"username": "nobody", "password": "x"})
check("unknown user -> same 401 and same message",
      r.status_code == 401 and r.json()["error"] == "wrong username or password")

r = s.post(f"{BASE}/login", json={"username": "juan",
                                  "password": "correct-horse-battery-staple"})
cookie_1 = s.cookies.get("__Host-session")
check("correct password -> asks for second factor", r.json().get("mfa_required") is True)
set_cookie = r.headers.get("Set-Cookie", "")
check("cookie with Secure, HttpOnly and SameSite=Lax",
      all(a in set_cookie for a in ("Secure", "HttpOnly", "SameSite=Lax")),
      set_cookie.split(";")[0][:30] + "...")

r = s.get(f"{BASE}/profile")
check("no access to /profile without second factor", r.status_code == 401)

r = s.post(f"{BASE}/login/mfa", json={"code": "000000"})
check("wrong TOTP code -> 401", r.status_code == 401)
code = totp(TOTP_SECRET)
r = s.post(f"{BASE}/login/mfa", json={"code": code})
cookie_2 = s.cookies.get("__Host-session")
check("correct TOTP code -> full session", r.status_code == 200, f"code {code}")
check("session ID changes on authentication (anti-fixation)", cookie_1 != cookie_2)

r = s.get(f"{BASE}/profile")
check("/profile with session", r.status_code == 200, r.text.strip())

r = s.post(f"{BASE}/logout", headers={"Origin": "https://attacker.example"})
check("CSRF: POST from another origin -> 403", r.status_code == 403)

# --- 3. API tokens ---------------------------------------------------------------

print("\n== JWT access token and refresh token")
r = s.post(f"{BASE}/api/token")
t = r.json()
access, refresh = t["access_token"], t["refresh_token"]
header, payload = decode_jwt(access)
check("access and refresh tokens issued", r.status_code == 200,
      f"alg={header['alg']}, exp-iat={payload['exp'] - payload['iat']} s, scope={payload['scope']}")

api = requests.Session()
api.verify = CA
api.trust_env = False
r = api.get(f"{BASE}/api/orders")
check("API without token -> 401", r.status_code == 401)
r = api.get(f"{BASE}/api/orders", headers={"Authorization": f"Bearer {access}"})
check("API with token -> 200", r.status_code == 200, r.text.strip())

# alg=none attack: same payload, no signature
forged = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
          + "." + access.split(".")[1] + ".")
r = api.get(f"{BASE}/api/orders", headers={"Authorization": f"Bearer {forged}"})
check("token with alg=none -> rejected", r.status_code == 401, r.json()["error"][:45])

# Modified payload: the signature no longer matches
hdr, pld, sig = access.split(".")
modified = dict(payload, sub="admin")
pld_mod = base64.urlsafe_b64encode(json.dumps(modified).encode()).rstrip(b"=").decode()
r = api.get(f"{BASE}/api/orders",
            headers={"Authorization": f"Bearer {hdr}.{pld_mod}.{sig}"})
check("token with changed sub -> rejected", r.status_code == 401)

r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
new_refresh = r.json().get("refresh_token")
check("refresh -> new token pair", r.status_code == 200 and new_refresh != refresh)
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
check("reusing the old refresh token -> 401", r.status_code == 401, r.json()["error"])
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": new_refresh})
check("after reuse, the whole family is revoked", r.status_code == 401)

# --- 4. Logout ---------------------------------------------------------------------

print("\n== Logout")
r = s.post(f"{BASE}/logout")
check("logout -> 200", r.status_code == 200)
fresh = requests.Session()
fresh.verify, fresh.trust_env = CA, False
r = fresh.get(f"{BASE}/profile", cookies={"__Host-session": cookie_2})
check("the old cookie no longer works (session deleted on the server)", r.status_code == 401)

print(f"\n{'All checks passed' if failures == 0 else f'{failures} checks failed'}")
sys.exit(1 if failures else 0)
```

### test\_auth.sh

```bash
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
```

### Actual test output

```
== auth_utils functions
[OK    ] salted Argon2id hash  ($argon2id$v=19$m=65536,t=3,p=4...)
[OK    ] two hashes of the same password differ
[OK    ] accepts the correct password
[OK    ] rejects a wrong one
[OK    ] TOTP matches the RFC 6238 test vector
[OK    ] PKCE S256 matches the RFC 7636 test vector
[OK    ] PKCE generates a 43-character code_verifier  (challenge=X9GZIs-hH7ez...)

== Cookie session and second factor
[OK    ] wrong password -> 401
[OK    ] unknown user -> same 401 and same message
[OK    ] correct password -> asks for second factor
[OK    ] cookie with Secure, HttpOnly and SameSite=Lax  (__Host-session=iYNWwzNLEcNLR0_...)
[OK    ] no access to /profile without second factor
[OK    ] wrong TOTP code -> 401
[OK    ] correct TOTP code -> full session  (code 380404)
[OK    ] session ID changes on authentication (anti-fixation)
[OK    ] /profile with session  ({"user":"juan"})
[OK    ] CSRF: POST from another origin -> 403

== JWT access token and refresh token
[OK    ] access and refresh tokens issued  (alg=ES256, exp-iat=900 s, scope=orders:read)
[OK    ] API without token -> 401
[OK    ] API with token -> 200  ({"orders":[{"id":1,"total":42.5}],"user":"juan"})
[OK    ] token with alg=none -> rejected  (invalid access token: The specified alg value)
[OK    ] token with changed sub -> rejected
[OK    ] refresh -> new token pair
[OK    ] reusing the old refresh token -> 401  (refresh token reused: session revoked)
[OK    ] after reuse, the whole family is revoked

== Logout
[OK    ] logout -> 200
[OK    ] the old cookie no longer works (session deleted on the server)

All checks passed
```

Two things that came up while testing:

- **Python 3.13 verifies certificates in strict X.509 mode** and rejects a CA without the `keyUsage` extension. That is why the certificates in Appendices B and C carry `keyUsage`, `basicConstraints` and `extendedKeyUsage=serverAuth`. It is the same check browsers apply to real certificates.
- **`requests` ignores `session.verify` if the `REQUESTS_CA_BUNDLE` variable is set.** The client uses `trust_env = False` so it always uses `ca.pem` and does not go through environment proxies.
