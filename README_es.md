# TLS 1.2 y TLS 1.3 en profundidad

Nov 4, 2026 · @Juan Maria Gomez Lopez (juan-maria.gomez-lopez@tutamail.com)

## Qué es TLS y qué garantiza

HTTPS es HTTP dentro de un túnel TLS, normalmente sobre TCP en el puerto 443. TLS 1.3 hace el mismo trabajo que TLS 1.2 en la mitad de viajes de ida y vuelta, cifra casi todo el handshake y elimina las opciones inseguras.

TLS aporta tres garantías:

- **Confidencialidad:** nadie en medio puede leer el tráfico.
- **Integridad:** cualquier modificación se detecta y la conexión se corta.
- **Autenticación:** el certificado demuestra que hablas con el dueño del dominio. Con mTLS, el servidor también verifica al cliente.

TLS tiene dos partes:

- **Protocolo de handshake:** negocia versión y algoritmos, autentica al servidor y acuerda las claves.
- **Protocolo de registro (record):** trocea los datos en registros de hasta 16 KB y los cifra con las claves acordadas.

En los diagramas de este documento, `{...}` indica mensajes cifrados con claves de handshake y `[...]` mensajes cifrados con claves de aplicación.

## Certificados y cadena de confianza

El cifrado de TLS no sirve de nada si hablas con la persona equivocada: el certificado X.509 es lo que demuestra que la clave pública del servidor pertenece al dominio que has pedido, y esa prueba se apoya en una cadena de firmas que termina en una CA raíz en la que tu sistema ya confía.

### Qué contiene un certificado

| Campo | Qué es | Ejemplo |
| --- | --- | --- |
| Subject | A quién pertenece | `CN=ejemplo.com` |
| Issuer | Quién lo firmó | `CN=R11, O=Let's Encrypt` |
| Validity | `notBefore` y `notAfter` | 90 días en Let's Encrypt |
| Subject Public Key Info | La clave pública y su algoritmo | ECDSA P-256 o RSA 2048 |
| Subject Alternative Name (SAN) | Los nombres que cubre | `DNS:ejemplo.com, DNS:*.ejemplo.com` |
| Basic Constraints | Si puede firmar otros certificados | `CA:FALSE` en un certificado de servidor |
| Key Usage / Extended Key Usage | Para qué se puede usar la clave | `digitalSignature`, `serverAuth` |
| CRL Distribution Points / AIA | Dónde consultar revocación y descargar el intermedio | URLs de la CA |
| SCTs | Pruebas de que está en los registros de Certificate Transparency | Dos o más firmas de logs |

### Qué comprueba el cliente

La validación de la cadena está definida en RFC 5280 y la comprobación del nombre en RFC 9525:

1. **Construir la cadena:** hoja → intermedio(s) → raíz del almacén del sistema o del navegador. El servidor debe enviar los intermedios; la raíz no hace falta enviarla.
2. **Firmas:** cada certificado está firmado por la clave del siguiente.
3. **Restricciones:** los intermedios tienen `CA:TRUE` y `keyCertSign`; la hoja tiene `serverAuth` en Extended Key Usage. Python 3.13 y los navegadores rechazan cadenas que no cumplen esto (por eso los certificados de prueba de los anexos llevan estas extensiones).
4. **Fechas:** la hora actual está entre `notBefore` y `notAfter` en todos los eslabones.
5. **Nombre:** el dominio pedido aparece en el SAN. El campo CN ya no se usa para esto. Un comodín cubre solo una etiqueta: `*.ejemplo.com` vale para `www.ejemplo.com` pero no para `ejemplo.com` ni para `a.b.ejemplo.com`.
6. **Revocación:** que el certificado no haya sido revocado (ver abajo).
7. **Certificate Transparency:** Chrome y Safari exigen SCTs de varios logs independientes; sin ellos, el certificado se rechaza aunque la firma sea válida.

### Revocación: CRL, OCSP y por qué se acorta la vida de los certificados

- **CRL:** la CA publica la lista firmada de números de serie revocados. Los navegadores ya no la descargan en cada conexión, sino que reciben resúmenes agregados (CRLSets en Chrome, CRLite en Firefox).
- **OCSP:** el cliente pregunta a la CA por un certificado concreto. Revela a la CA qué webs visitas, así que se inventó el *OCSP stapling*: el servidor adjunta la respuesta firmada durante el handshake. Let's Encrypt dejó de incluir URLs de OCSP en mayo de 2025 y apagó sus servidores OCSP el 6 de agosto de 2025, por privacidad y coste; solo publica CRLs.
- **Vida corta:** como la revocación funciona mal a escala, la solución de la industria es que los certificados caduquen antes. La votación SC-081v3 del CA/Browser Forum (abril de 2025) reduce la validez máxima de 398 días a 200 días desde el 15 de marzo de 2026, 100 días desde el 15 de marzo de 2027 y 47 días desde el 15 de marzo de 2029. En la práctica obliga a renovar automáticamente con ACME (RFC 8555): certbot, acme.sh o el propio servidor (Caddy, Traefik).

Estos plazos se aplican a certificados de CAs públicas. Una CA privada, como la de los anexos o la de una empresa, define sus propias reglas, pero sus raíces hay que instalarlas a mano en cada cliente.

### Comprobar una cadena con OpenSSL

```bash
# Ver la cadena que envía el servidor y el resultado de la verificación
openssl s_client -connect ejemplo.com:443 -servername ejemplo.com -showcerts </dev/null \
  | grep -E 's:|i:|Verify return code'

# Verificar un certificado contra una CA y un intermedio concretos
openssl verify -CAfile raiz.pem -untrusted intermedio.pem servidor.pem

# Ver las extensiones relevantes
openssl x509 -in servidor.pem -noout -ext subjectAltName,basicConstraints,keyUsage,extendedKeyUsage
```

## TLS 1.2: handshake completo con ECDHE

Un handshake completo de TLS 1.2 cuesta dos viajes de ida y vuelta (2-RTT) antes de poder enviar la primera petición HTTP. Este es el caso más habitual, con una suite como `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.

&#91;embedded content: Handshake TLS 1.2 con ECDHE · 11 mensajes en 2 RTT\]

### Qué aporta cada mensaje

- **ClientHello / ServerHello:** cada lado envía 32 bytes aleatorios (`client_random`, `server_random`). El cliente ofrece suites y extensiones, y el servidor elige una.
- **Certificate:** el certificado viaja **en claro**. Cualquiera que observe el tráfico ve a qué servidor te conectas.
- **ServerKeyExchange:** la clave pública ECDHE efímera del servidor, **firmada** con la clave privada del certificado. Esa firma impide que alguien en medio meta su propia clave.
- **ServerHelloDone:** el servidor termina su primer vuelo.
- **ClientKeyExchange:** la clave pública ECDHE del cliente. Con ella, los dos lados calculan el *pre-master secret*.
- **ChangeCipherSpec:** no es un mensaje del handshake, sino un tipo de registro aparte que significa "a partir de aquí, cifro". Es un artefacto histórico de SSL.
- **Finished:** contiene `verify_data`, un resumen de todos los mensajes anteriores. Si un atacante alteró alguno (por ejemplo, borró las suites fuertes del ClientHello), los resúmenes no coinciden y se aborta.

### Derivación de claves

TLS 1.2 usa su propia PRF (Pseudo-Random Function o Función Pseudo-aleatoria), basada en HMAC-SHA256:

```
master_secret = PRF(pre_master, "master secret", client_random + server_random)   → 48 bytes
key_block     = PRF(master_secret, "key expansion", server_random + client_random)
                → claves de cifrado, claves MAC e IVs de cada sentido
verify_data   = PRF(master_secret, "client finished", Hash(mensajes del handshake))   → 12 bytes
```

La extensión *Extended Master Secret* (RFC 7627) sustituye los randoms por el hash de todo el handshake. Así se evita el ataque *triple handshake*.

### Variante RSA y reanudación

- **Intercambio RSA** (por ejemplo `TLS_RSA_WITH_AES_128_GCM_SHA256`): no hay ServerKeyExchange. El cliente genera el pre-master y lo cifra con la clave pública RSA del certificado. Si alguien obtiene después esa clave privada, puede descifrar todas las sesiones grabadas: no hay forward secrecy.
- **Reanudación:** con *Session ID* (el servidor guarda la sesión en caché) o con *Session Tickets* (el servidor cifra el estado y se lo da al cliente). Las dos reducen el handshake a 1-RTT. La clave que cifra los tickets suele durar mucho y, si se filtra, rompe el forward secrecy.
- **Renegociación:** permite repetir el handshake dentro de una conexión ya abierta. Fue fuente de vulnerabilidades y TLS 1.3 la elimina.

### Precisiones de TLS 1.2

**Anatomía del nombre de una suite:**

```
TLS_ ECDHE _ RSA _WITH_ AES_128_GCM _ SHA256
     │        │           │             └─ hash de la PRF (y del MAC si no es AEAD)
     │        │           └─ cifrado del registro
     │        └─ algoritmo de la firma del servidor (tipo de certificado)
     └─ intercambio de claves
```

OpenSSL usa otros nombres para las mismas suites: `ECDHE-RSA-AES128-GCM-SHA256`. Es el formato que aparece en la salida del Anexo B.

**Lo que firma exactamente el ServerKeyExchange:** `client_random || server_random || ServerECDHParams` (el tipo de curva, el grupo y el punto público). Incluir los dos randoms impide reutilizar una firma de otra sesión. Lo que **no** firma es la lista de suites del ClientHello. Esa protección depende solo del Finished, y es la puerta que aprovecharon ataques de downgrade como Logjam o FREAK contra servidores que aún aceptaban suites de exportación.

**Tamaños:** los randoms tienen 32 bytes, el `session_id` hasta 32 bytes, el master secret 48 bytes y `verify_data` 12 bytes. El registro transporta como máximo 2^14 bytes (16 KB) de texto en claro.

**Extensiones de seguridad que un servidor TLS 1.2 debe soportar:**

| Extensión | RFC | Para qué |
| --- | --- | --- |
| `renegotiation_info` | 5746 | Ata cada renegociación a la conexión anterior; sin ella hay inyección de texto al principio de la sesión |
| `extended_master_secret` | 7627 | Deriva el master secret del hash de todo el handshake (ataque *triple handshake*) |
| `encrypt_then_mac` | 7366 | Con suites CBC, calcula el MAC sobre el texto cifrado (Lucky13, padding oracle) |
| `supported_groups` y `signature_algorithms` | 8422, 5246 | Negocian curvas y algoritmos de firma |
| `server_name` (SNI) y ALPN | 6066, 7301 | Nombre del sitio y protocolo de aplicación |
| `session_ticket` | 5077 | Reanudación sin estado en el servidor |

**Configuración recomendable si aún hay que ofrecer TLS 1.2:** solo intercambio ECDHE (o DHE con grupos de al menos 2048 bits) y cifrado AEAD. Por ejemplo, en nginx:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

`ssl_ciphers` solo afecta a TLS 1.2. Las suites de TLS 1.3 se configuran aparte (`ssl_conf_command Ciphersuites ...`), y sus valores por defecto ya son seguros.

## TLS 1.3: handshake completo

TLS 1.3 completa el handshake en un solo viaje de ida y vuelta (1-RTT): el cliente manda su parte de Diffie-Hellman ya en el ClientHello, y todo lo que sigue al ServerHello, incluido el certificado, va cifrado.

&#91;embedded content: Handshake TLS 1.3 completo · 1 RTT, con mTLS opcional\]

### Qué aporta cada mensaje

- **ClientHello:** versiones (`supported_versions`), grupos y su `key_share` (por ejemplo X25519), algoritmos de firma (`signature_algorithms`), SNI y ALPN.
- **ServerHello:** el `key_share` del servidor y la versión elegida. Desde aquí los dos lados tienen el secreto ECDHE y derivan las claves de handshake.
- **EncryptedExtensions:** el resto de parámetros, como el ALPN elegido. En 1.2 iban en claro en el ServerHello.
- **CertificateRequest:** solo si el servidor pide certificado al cliente (mTLS).
- **Certificate:** la cadena X.509, ya cifrada.
- **CertificateVerify:** una firma con la clave privada del certificado sobre el hash de **toda la transcripción**, no solo sobre la clave ECDHE como en 1.2. Si la clave es RSA, esta firma debe ser RSA-PSS (rsa\_pss\_rsae\_\*); el certificado en sí puede seguir firmado por la CA con PKCS#1 v1.5.
- **Finished:** un HMAC sobre toda la transcripción. Tras el Finished del cliente, todo va con claves de aplicación.

ServerKeyExchange, ClientKeyExchange, ServerHelloDone y ChangeCipherSpec desaparecen como mensajes. El servidor puede incluso enviar datos justo después de su Finished ("0,5-RTT"), aunque en ese momento aún no ha verificado al cliente.

### Compatibilidad y protección contra downgrade

- **Versión disfrazada:** para no romper firewalls y proxies antiguos (*middleboxes*), el campo de versión sigue diciendo `0x0303` (TLS 1.2). La versión real se negocia en la extensión `supported_versions`. Por el mismo motivo, el cliente puede enviar un ChangeCipherSpec falso que se ignora (*middlebox compatibility mode*).
- **Marca de downgrade:** si un servidor que soporta 1.3 acaba negociando 1.2, pone los 8 últimos bytes del `server_random` a `DOWNGRD\x01`. Un cliente 1.3 que vea esa marca sabe que alguien manipuló el ClientHello, y aborta. En hexadecimal son 44 4F 57 4E 47 52 44 01; si se negocia TLS 1.1 o anterior, el último byte es 00. La marca funciona porque el server\_random va firmado (en 1.2, dentro del ServerKeyExchange).
- **HelloRetryRequest (HRR):** si el grupo del `key_share` no le vale al servidor, este pide otro. El cliente repite el ClientHello y el handshake pasa a 2-RTT. Por eso los clientes envían key\_shares de los grupos más probables.
- **Intercambio post-cuántico:** el grupo híbrido X25519MLKEM768 concatena un intercambio X25519 y un encapsulado ML-KEM-768, y el secreto solo cae si se rompen los dos. Protege frente a quien grabe el tráfico hoy para descifrarlo con un ordenador cuántico. Es el grupo por defecto en Chrome y Edge 131+, Firefox 132+ (escritorio), Safari 26, Go 1.24+ y OpenSSL 3.5+. El key\_share pasa de 32 bytes a unos 1.200, y el ClientHello crece hasta unos 1.300-1.500 bytes, lo que ha roto algunos firewalls que esperaban el ClientHello en un solo paquete. La OpenSSL 3.0 de Ubuntu 24.04 o Debian 12 aún no lo soporta.

### Precisiones de TLS 1.3

**Las cinco suites de TLS 1.3** (RFC 8446, apéndice B.4). Solo indican el cifrado AEAD y el hash del key schedule:

| Suite | Código | Notas |
| --- | --- | --- |
| `TLS_AES_128_GCM_SHA256` | 0x1301 | Obligatoria para cualquier implementación |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | Habitual por defecto en OpenSSL |
| `TLS_CHACHA20_POLY1305_SHA256` | 0x1303 | Preferida sin AES por hardware (móviles antiguos, ARM pequeños) |
| `TLS_AES_128_CCM_SHA256` | 0x1304 | IoT; desactivada por defecto en OpenSSL |
| `TLS_AES_128_CCM_8_SHA256` | 0x1305 | Tag de 8 bytes; no recomendada para uso general |

**HelloRetryRequest no es un mensaje nuevo:** es un ServerHello cuyo `random` es el SHA-256 de la cadena "HelloRetryRequest" (`CF21AD74E59A6111...`). En la transcripción, el primer ClientHello se sustituye por un mensaje sintético con su hash.

**Qué firma exactamente CertificateVerify:** 64 bytes `0x20`, la cadena `"TLS 1.3, server CertificateVerify"`, un byte `0x00` y el hash de la transcripción hasta Certificate. El relleno inicial y la cadena de contexto impiden reutilizar la firma en otro protocolo o en el otro sentido (el cliente usa `"TLS 1.3, client CertificateVerify"`).

**Cómo se calcula Finished:**

```
finished_key = HKDF-Expand-Label(handshake_traffic_secret, "finished", "", Hash.length)
verify_data  = HMAC(finished_key, Transcript-Hash(ClientHello ... CertificateVerify))
```

**Compatibilidad con middleboxes:** el cliente rellena `legacy_session_id` con 32 bytes aleatorios y el servidor los devuelve, y los dos pueden enviar un ChangeCipherSpec ficticio (`0x01`) que se ignora. Así, para un firewall antiguo, el handshake parece una reanudación de TLS 1.2.

**Autenticación del cliente después del handshake:** si el cliente envía la extensión `post_handshake_auth`, el servidor puede pedirle certificado más tarde, por ejemplo al entrar en `/admin`. Sustituye a la renegociación que se usaba en 1.2 para esto. HTTP/2 la prohíbe, así que en la práctica se usa poco.

## TLS 1.3: derivación de claves (key schedule)

TLS 1.3 sustituye la PRF de 1.2 por tres escalones de HKDF. Cada escalón mezcla una entrada nueva y produce sus propias claves de tráfico, cada una ligada a los mensajes exactos del handshake.

&#91;embedded content: Key schedule de TLS 1.3 · tres escalones de HKDF\]

- **Extract:** en cada escalón, `HKDF-Extract` mezcla la entrada nueva (el PSK, el secreto ECDHE o ceros) con el secreto del escalón anterior. Entre escalones se aplica `Derive-Secret(secreto, "derived", "")`.
- **Claves ligadas a la transcripción:** las claves de tráfico salen de `Derive-Secret(secreto, etiqueta, Hash(transcripción))`. `c hs traffic` usa el hash de ClientHello+ServerHello; `c ap traffic`, el hash hasta el Finished del servidor.
- **Clave e IV:** de cada *traffic secret* salen `HKDF-Expand-Label(secret, "key", "", longitud)` y `HKDF-Expand-Label(secret, "iv", "", 12)`, distintas en cada sentido.
- **Otros secretos del Master Secret:** el *resumption master secret*, del que salen los PSK de los tickets, y el *exporter secret*, con el que otros protocolos derivan claves ligadas a esta sesión TLS (el channel binding tls-exporter de RFC 9266, EAP-TLS o, en DTLS, el SRTP de WebRTC). QUIC no usa el exporter: toma directamente los secretos de tráfico de handshake y de aplicación para proteger sus paquetes (RFC 9001).
- **KeyUpdate:** en conexiones largas, cada lado puede rotar sus claves de aplicación (la N+1 se deriva de la N) sin repetir el handshake.

Las claves ECDHE son efímeras y se descartan al cerrar la conexión. Esto da **forward secrecy**: robar más tarde la clave privada del certificado no permite descifrar el tráfico grabado, porque esa clave solo firma.

#### Las fórmulas exactas (RFC 8446, sección 7.1)

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)
    donde HkdfLabel = uint16(Length) || opaque("tls13 " + Label) || opaque(Context)

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
              +--> Derive-Secret(., "c ap traffic", ClientHello...Finished del servidor)
              +--> Derive-Secret(., "s ap traffic", ClientHello...Finished del servidor)
              +--> Derive-Secret(., "exp master",   ClientHello...Finished del servidor)
              +--> Derive-Secret(., "res master",   ClientHello...Finished del cliente)

Clave e IV de registro:
    key = HKDF-Expand-Label(traffic_secret, "key", "", longitud_clave)   # 16 o 32 bytes
    iv  = HKDF-Expand-Label(traffic_secret, "iv",  "", 12)

KeyUpdate:
    application_traffic_secret_N+1 = HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)

PSK de un ticket:
    PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
```

En `HKDF-Extract`, el secreto del escalón anterior hace de *sal* y la entrada nueva de *material de clave*. Sin PSK, la entrada del primer escalón es una cadena de ceros de la longitud del hash. `Hash` es SHA-256 o SHA-384, según la suite.

Estas fórmulas se pueden ver en acción: el fichero de claves que genera `SSLKEYLOGFILE` (o el callback del Anexo B) contiene exactamente `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` y `EXPORTER_SECRET`.

## TLS 1.3: reanudación con PSK y 0-RTT

Con un ticket de una conexión anterior, el cliente puede reconectar sin validar de nuevo el certificado y enviar la petición HTTP en el primer vuelo (0-RTT). El precio es que esos primeros datos se pueden reenviar.

&#91;embedded content: Reanudación TLS 1.3 con PSK y datos 0-RTT\]

- **El ticket:** tras una conexión completa, el servidor manda uno o varios **NewSessionTicket**, ya cifrados. Cada uno lleva un identificador opaco, un tiempo de vida (máximo 7 días) y un `ticket_age_add` que ofusca su edad.
- **El binder:** la extensión `pre_shared_key` del ClientHello incluye el ticket y un HMAC calculado con el PSK sobre el propio ClientHello. Demuestra que el cliente posee el PSK y no está reutilizando el ticket de otro.
- **Sin certificado:** el servidor ya se autenticó en la conexión original, así que no envía Certificate ni CertificateVerify.
- **Forward secrecy:** el modo recomendado, `psk_dhe_ke`, mezcla el PSK con un ECDHE nuevo. El modo `psk_ke`, solo con PSK, es más rápido pero no tiene forward secrecy.
- **EndOfEarlyData:** el cliente lo envía para cerrar la fase 0-RTT y pasar a las claves de handshake.

### El riesgo del 0-RTT

Los datos 0-RTT se cifran con claves que salen **solo del PSK**. No tienen forward secrecy y, sobre todo, un atacante puede capturar ese primer vuelo y **reenviarlo (replay)**. Las defensas habituales:

- Aceptar solo métodos idempotentes (GET) en 0-RTT, nunca un POST que haga un pago.
- Mantener en el servidor una caché anti-replay.
- Usar la cabecera `Early-Data: 1` (RFC 8470), con la que un backend puede responder `425 Too Early`.

Muchos servidores dejan el 0-RTT desactivado por defecto.

#### Precisiones de la reanudación

- **Binder:** es un HMAC calculado con una clave derivada del PSK (`binder_key`, etiqueta `"res binder"` para tickets) sobre el ClientHello **truncado** justo antes de la lista de binders. Por eso la extensión `pre_shared_key` debe ser la última del ClientHello.
- **Edad del ticket:** el cliente envía `obfuscated_ticket_age = (edad_en_ms + ticket_age_add) mod 2^32`. El servidor la desofusca y la compara con la edad real; si difieren mucho, rechaza el 0-RTT (es una defensa contra replays fuera de plazo).
- **Vida del ticket:** como máximo 604.800 segundos (7 días). Un PSK solo se puede usar con una suite que tenga el mismo hash que la original.
- **Cuántos datos 0-RTT:** el ticket indica `max_early_data_size`. El servidor acepta o rechaza el 0-RTT con la extensión `early_data` en EncryptedExtensions. Si lo rechaza, el cliente reenvía esos datos después del handshake, con claves normales.
- **Anti-replay (RFC 8446, sección 8):** tickets de un solo uso, un registro de los ClientHello ya vistos dentro de una ventana de tiempo, y comprobación de la edad del ticket. Ninguno impide el replay entre varios servidores que no compartan estado, así que la aplicación sigue teniendo que tratar los datos 0-RTT como repetibles.

## El registro cifrado: 1.2 frente a 1.3

En TLS 1.3, un observador ya no puede distinguir qué tipo de mensaje viaja en cada registro, y el nonce deja de transmitirse. La cabecera sigue teniendo 5 bytes en las dos versiones: tipo, versión y longitud.

&#91;embedded content: Registro cifrado · TLS 1.2 con AES-GCM frente a TLS 1.3\]

- **Tipo de contenido oculto:** en 1.2 se distinguen los registros de handshake, de alerta y de aplicación. En 1.3, la cabecera siempre dice `application_data` (23) con versión `0x0303`, y el tipo real va dentro del cifrado.
- **Padding opcional:** en 1.3 se pueden rellenar los registros para ocultar el tamaño real de los mensajes y dificultar el análisis de tráfico.
- **Nonce:** en 1.2 con GCM, 8 bytes del nonce iban en cada registro, y las implementaciones que los repetían rompían la seguridad de GCM. En 1.3, el nonce es `IV XOR número_de_secuencia`: no ocupa espacio y no se repite mientras el contador avance.
- **Número de secuencia:** no se transmite en ninguna versión, pero entra en el cálculo. Si se reordena o se pierde un registro, el descifrado falla.
- **Datos autenticados (AAD):** en 1.3 son la propia cabecera de 5 bytes. En 1.2 eran el número de secuencia, el tipo, la versión y la longitud.
- **Algoritmos:** 1.3 solo admite cifrados AEAD (AES-GCM, ChaCha20-Poly1305, AES-CCM). Desaparecen CBC (atacado por Lucky13 y POODLE), RC4 y 3DES.

#### Cifras exactas del registro

|  | TLS 1.2 (AES-GCM) | TLS 1.3 |
| --- | --- | --- |
| Texto en claro máximo | 2^14 bytes (16.384) | 2^14 bytes, más el byte de tipo y el padding |
| Texto cifrado máximo | 2^14 + 2.048 bytes | 2^14 + 256 bytes |
| Nonce | 4 bytes implícitos (del key\_block) + 8 explícitos en el registro | IV de 12 bytes XOR número de secuencia de 64 bits |
| Datos autenticados (AAD) | 13 bytes: secuencia (8) + tipo (1) + versión (2) + longitud (2) | 5 bytes: la cabecera del registro |
| Contenido cifrado | Solo los datos | `TLSInnerPlaintext` = datos + tipo real (1 byte) + ceros de relleno |

ChaCha20-Poly1305 en TLS 1.2 (RFC 7905) ya usaba un nonce implícito como el de 1.3, sin bytes explícitos.

**Límite de uso de cada clave:** RFC 8446 (sección 5.5) pide no cifrar más de unos 2^24,5 registros completos (unos 24 millones, alrededor de 380 GB) con la misma clave AES-GCM. Antes de llegar ahí, la implementación envía un KeyUpdate. Con ChaCha20-Poly1305 el límite es tan alto que el número de secuencia se agotaría antes.

## Resumen de diferencias

| Aspecto | TLS 1.2 | TLS 1.3 |
| --- | --- | --- |
| Handshake completo | 2-RTT | 1-RTT (2 si hay HelloRetryRequest) |
| Reanudación | 1-RTT (Session ID o ticket) | 1-RTT con PSK, o 0-RTT |
| Intercambio de claves | RSA, DHE, ECDHE | Solo (EC)DHE o PSK(+DHE) |
| Forward secrecy | Opcional | Siempre, salvo psk\_ke y 0-RTT |
| Firma del servidor | Sobre los parámetros DH | Sobre toda la transcripción |
| Derivación de claves | PRF de TLS (HMAC) | HKDF en tres escalones |
| Certificado | En claro | Cifrado |
| Suite de cifrado | Intercambio + autenticación + cifrado + MAC | Solo AEAD + hash |
| Modos de cifrado | CBC, RC4, 3DES, GCM... | Solo AEAD |
| Renegociación | Sí | No (KeyUpdate y autenticación post-handshake) |
| Tipo de registro | Visible | Oculto, con padding opcional |

SSL 3.0, TLS 1.0 y TLS 1.1 están obsoletos y deberían estar desactivados.

## Lo que TLS no oculta

- La **IP y el puerto** de destino.
- El **SNI**, en claro en el ClientHello: se ve el dominio aunque no la URL. La extensión ECH (Encrypted Client Hello, RFC 9849, noviembre de 2025) cifra un ClientHello interior completo, con el SNI real y el ALPN, con una clave HPKE que el servidor publica en DNS (registros HTTPS/SVCB). Hacia fuera solo se ve un ClientHello exterior con un nombre genérico del proveedor. Su despliegue aún es parcial y depende también de usar DNS cifrado.
- El **tamaño y el ritmo** del tráfico.
- La consulta **DNS**, salvo que uses DoH o DoT.

La ruta, los parámetros, las cabeceras, las cookies y el cuerpo sí van cifrados.

## Comprobarlo en tu propio tráfico

Forzar cada versión y ver los mensajes del handshake en orden. En 1.2 aparecen ServerKeyExchange y ServerHelloDone; en 1.3, EncryptedExtensions justo detrás del ServerHello:

```bash
openssl s_client -connect ejemplo.com:443 -servername ejemplo.com -tls1_2 -msg
openssl s_client -connect ejemplo.com:443 -servername ejemplo.com -tls1_3 -msg
```

Ver los datos del certificado (emisor, fechas, SAN):

```bash
echo | openssl s_client -connect ejemplo.com:443 -servername ejemplo.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Exportar las claves de sesión y cargarlas en Wireshark para descifrar la captura:

```bash
SSLKEYLOGFILE=/tmp/keys.log curl -s https://ejemplo.com > /dev/null
```

Para auditar la configuración de un servidor (versiones, cifrados, cadena de certificados y vulnerabilidades conocidas), `testssl.sh` lo revisa todo de una pasada.

## Autenticación web en detalle

Toda autenticación web resuelve dos problemas distintos: demostrar una vez quién eres (login) y, después, que cada petición posterior lleve una prueba de esa identidad sin repetir el login. TLS protege esa prueba mientras viaja, pero no la sustituye.

### Conceptos base

- **Autenticación (AuthN):** comprobar quién es el usuario. Responde a "¿quién eres?".
- **Autorización (AuthZ):** decidir qué puede hacer. Responde a "¿puedes hacer esto?". OAuth 2.0 es, sobre todo, un protocolo de autorización; OpenID Connect añade la autenticación encima.
- **Factores:** algo que sabes (contraseña, PIN), algo que tienes (móvil, llave de seguridad) y algo que eres (huella, cara). MFA combina al menos dos factores distintos.
- **Con estado (stateful):** el servidor guarda la sesión y el cliente solo lleva un identificador aleatorio. Revocar es inmediato: se borra la sesión.
- **Sin estado (stateless):** el cliente lleva un token firmado con toda la información y el servidor solo verifica la firma. Escala sin almacén compartido, pero revocar antes de la caducidad es difícil.
- **Credencial portadora (bearer):** quien la tenga, la usa. Cookies de sesión, tokens de acceso y API keys son bearer: si se roban, el atacante se hace pasar por el usuario. Por eso solo deben viajar por HTTPS.
- **Credencial ligada (proof-of-possession):** solo sirve si además demuestras poseer una clave privada. Es el caso de mTLS, WebAuthn y los tokens DPoP.

### Dónde viaja la credencial en HTTP

| Mecanismo | Cabecera o lugar | Lo envía |
| --- | --- | --- |
| Cookie de sesión | `Cookie: session=...` | El navegador, automáticamente |
| Token de acceso | `Authorization: Bearer <token>` | El código del cliente, a mano |
| HTTP Basic | `Authorization: Basic base64(usuario:clave)` | El navegador o el cliente |
| API key | `X-API-Key: ...` o `Authorization` | El cliente |
| Certificado de cliente | Dentro del handshake TLS | La pila TLS del cliente |

&#91;embedded content: Mecanismos de autenticación web · 3 fases\]

### Contraseñas: cómo se guardan y cómo se envían

Una contraseña nunca se guarda tal cual ni cifrada: se guarda un hash lento con sal. Si roban la base de datos, el atacante tiene que probar candidatas una a una, y cada prueba le cuesta tiempo y memoria.

**Almacenamiento correcto:**

- **Algoritmo:** Argon2id es la opción recomendada. bcrypt y scrypt son aceptables; PBKDF2 solo con muchas iteraciones o cuando se exige FIPS (Federal Information Processing Standards o Estándares Federales de Procesamiento de la Información).
- **Sal:** un valor aleatorio distinto por usuario, guardado junto al hash. Impide las tablas precalculadas y que dos usuarios con la misma contraseña tengan el mismo hash.
- **Coste:** se ajusta para que verificar tarde del orden de cientos de milisegundos. Lo bastante lento para frenar un ataque masivo y lo bastante rápido para un login normal.
- **Nunca:** MD5, SHA-1 o SHA-256 a pelo. Son rápidos a propósito, y una GPU prueba miles de millones por segundo.

**Parámetros mínimos recomendados por OWASP:**

| Algoritmo | Mínimo | Observaciones |
| --- | --- | --- |
| Argon2id | m = 19 MiB (19.456 KiB), t = 2, p = 1; o m = 46 MiB, t = 1 | Primera opción. RFC 9106 sugiere m = 64 MiB, t = 3 si se puede permitir |
| scrypt | N = 2^17, r = 8, p = 1 | Si no hay Argon2id |
| bcrypt | Coste 10 o más | Solo usa los primeros 72 bytes de la contraseña |
| PBKDF2 | 600.000 iteraciones con HMAC-SHA-256 | Solo si se exige FIPS 140 |

La librería `argon2-cffi` del Anexo C usa por defecto el perfil de RFC 9106 (m = 64 MiB, t = 3, p = 4), por eso su hash empieza por `$argon2id$v=19$m=65536,t=3,p=4`. La memoria se consume por cada login simultáneo: 100 logins a la vez con 64 MiB necesitan unos 6,4 GB, así que hay que medir antes de subir los parámetros. Una *pepper* (un secreto común añadido antes del hash y guardado fuera de la base de datos, en un almacén de secretos o un HSM) añade protección si solo se roba la base de datos.

Un hash Argon2id guardado tiene este aspecto, con algoritmo, parámetros, sal y hash en una sola cadena:

```
$argon2id$v=19$m=65536,t=3,p=4$c2FsdGFsZWF0b3JpYQ$hJ3k...
```

**Verificación en el login:** el servidor recalcula el hash con la sal guardada y compara en tiempo constante. Si el usuario no existe, conviene calcular igualmente un hash ficticio para que el tiempo de respuesta no revele qué usuarios existen.

**Otras buenas prácticas:** limitar intentos por cuenta y por IP, comprobar las contraseñas nuevas contra listas de contraseñas filtradas, permitir contraseñas largas y no obligar a cambiarlas periódicamente sin motivo.

#### HTTP Basic y Digest

Son los mecanismos nativos de HTTP. El servidor responde `401 Unauthorized` con `WWW-Authenticate` y el cliente repite la petición con `Authorization`.

```
GET /admin HTTP/1.1
← 401 Unauthorized
  WWW-Authenticate: Basic realm="Admin"

GET /admin HTTP/1.1
Authorization: Basic anVhbjpzZWNyZXRv      ← base64("juan:secreto")
← 200 OK
```

- **Basic (RFC 7617):** base64 no es cifrado, así que la contraseña viaja en claro dentro de TLS y se envía en **cada** petición. No hay cierre de sesión real: el navegador la recuerda hasta que se cierra. Es válido para herramientas internas o APIs sencillas, siempre sobre HTTPS.
- **Digest (RFC 7616):** envía un hash de la contraseña con un nonce del servidor en vez de la contraseña. Obliga al servidor a guardar la contraseña (o un hash rápido equivalente), así que hoy apenas se usa: Basic sobre TLS con hash lento en el servidor es más seguro.

### Sesiones con cookies

Es el mecanismo clásico de las aplicaciones web con navegador: tras el login, el servidor guarda la sesión y le da al navegador un identificador aleatorio en una cookie, que el navegador reenvía solo en cada petición.

&#91;embedded content: Sesión con cookie · login, petición y logout\]

#### El flujo, paso a paso

1. **Login:** el usuario envía usuario y contraseña por `POST /login`, nunca por GET (acabaría en logs e historial).
2. **Verificación:** el servidor comprueba el hash de la contraseña y, si hay MFA, pide el segundo factor.
3. **Creación de la sesión:** genera un ID con al menos 128 bits de un generador criptográfico y guarda en el almacén (memoria, Redis o base de datos) el usuario, la fecha de creación, la de última actividad y lo que necesite.
4. **Set-Cookie:** responde con la cookie y sus atributos de seguridad:

   ```
   Set-Cookie: __Host-session=k3J9xQ...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
   ```
5. **Peticiones posteriores:** el navegador añade `Cookie: __Host-session=k3J9xQ...` en cada petición a ese dominio. El servidor busca el ID en el almacén, comprueba que no ha caducado y recupera el usuario.
6. **Logout:** el servidor **borra la sesión del almacén** y responde con la cookie caducada. Borrar solo la cookie en el navegador no basta: quien hubiera copiado el ID podría seguir usándolo.

#### Atributos de la cookie

| Atributo | Qué hace | Contra qué protege |
| --- | --- | --- |
| `Secure` | Solo se envía por HTTPS | Robo en una red sin cifrar |
| `HttpOnly` | JavaScript no puede leerla | Robo de la sesión mediante XSS |
| `SameSite=Lax` | Desde otro sitio solo se envía al navegar con un enlace o un GET de nivel superior; no en POST, iframes, imágenes ni fetch | CSRF |
| `SameSite=Strict` | No se envía en ninguna petición iniciada desde otro sitio, ni siquiera al seguir un enlace | CSRF, a costa de comodidad |
| `SameSite=None` | Se envía siempre (exige `Secure`) | Nada; solo para casos entre sitios, como iframes de terceros |
| `Max-Age` / `Expires` | Caducidad en el navegador | Sesiones olvidadas abiertas |
| `Domain` | Amplía la cookie a subdominios | Mejor no ponerlo: sin él, solo la recibe el host exacto |
| Prefijo `__Host-` | El navegador exige `Secure`, `Path=/` y ninguna `Domain` | Que un subdominio comprometido sobrescriba la cookie |

Dos detalles de `SameSite` que suelen confundirse:

- **Sitio no es origen.** Un *sitio* es el esquema más el dominio registrable (`https://ejemplo.com`); un *origen* incluye además el subdominio y el puerto. `app.ejemplo.com` y `blog.ejemplo.com` son el mismo sitio, así que `SameSite` no protege de un subdominio comprometido. Para eso están el prefijo `__Host-` y la comprobación de `Origin`.
- **El valor por defecto depende del navegador.** Chrome y Edge tratan como `Lax` las cookies que no declaran `SameSite`; Firefox y Safari no. Por eso hay que declararlo siempre.

#### Ataques típicos y defensas

- **CSRF (Cross-Site Request Forgery):** una web maliciosa hace que el navegador envíe una petición a tu aplicación, y la cookie se añade sola. Se defiende con `SameSite`, un token anti-CSRF en los formularios (que el atacante no puede leer) y comprobando las cabeceras `Origin` o `Sec-Fetch-Site` en las peticiones que cambian estado.
- **Fijación de sesión:** el atacante consigue que la víctima use un ID de sesión que él conoce, y espera a que haga login. Se evita **generando un ID nuevo al autenticar** y siempre que cambien los privilegios.
- **Robo de la cookie:** mediante XSS, malware o un proxy comprometido. `HttpOnly` cierra la vía XSS; lo demás se mitiga con caducidad por inactividad (por ejemplo 30 minutos), caducidad absoluta (por ejemplo 12 horas) y pidiendo de nuevo la contraseña antes de acciones críticas.

**Ventajas:** revocación inmediata, el navegador la gestiona solo y `HttpOnly` la protege de XSS. **Inconvenientes:** necesita un almacén de sesiones compartido entre servidores, hay que defenderse de CSRF y encaja mal fuera del navegador (apps móviles, APIs entre servicios).

### Tokens: opacos y JWT

Un token es una credencial que el cliente envía en la cabecera `Authorization: Bearer <token>`. Puede ser **opaco** (una cadena aleatoria que el servidor busca en su base de datos, como un ID de sesión) o **autocontenido**, como un JWT, que lleva los datos dentro y una firma que el servidor verifica sin consultar nada.

#### Estructura de un JWT (RFC 7519)

Tres partes en base64url separadas por puntos: `cabecera.carga.firma`.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqdWFuIiwiZXhwIjoxNzk....SflKxwRJSMeKKF2QT4fwpM...
```

```json
// Cabecera
{ "alg": "RS256", "typ": "JWT", "kid": "clave-2026-11" }

// Carga (claims)
{
  "iss": "https://auth.ejemplo.com",   // quién lo emite
  "sub": "user-1234",                  // a quién se refiere
  "aud": "https://api.ejemplo.com",    // para quién es
  "iat": 1793780000,                   // emitido en (segundos Unix)
  "exp": 1793780900,                   // caduca en: 15 minutos después
  "jti": "5f2b9c...",                  // ID único, útil para revocar
  "scope": "pedidos:leer"
}

// Firma
RSASSA-PKCS1-v1_5-SHA256( base64url(cabecera) + "." + base64url(carga), clave_privada )
```

La carga va **firmada, no cifrada**: cualquiera puede leerla decodificando el base64url. Nunca metas en un JWT contraseñas ni datos personales sensibles. Si hace falta cifrarlo, existe JWE.

#### Algoritmos de firma

- **HS256 (HMAC):** una clave secreta compartida. El que verifica también puede emitir, así que solo vale cuando emisor y verificador son el mismo servicio.
- **RS256 / PS256 (RSA) y ES256 / EdDSA (curvas elípticas):** el emisor firma con su clave privada y cualquier servicio verifica con la pública. Las claves públicas suelen publicarse en un endpoint JWKS (`/.well-known/jwks.json`), y el campo `kid` indica cuál usar, lo que permite rotarlas.

#### Validación correcta: lo que el servidor debe comprobar

1. Que el `alg` es el que **tú esperas**, fijado en el código. Nunca aceptes el que diga la cabecera: así funcionan los ataques `alg: none` y de confusión RS256/HS256 (firmar con HMAC usando la clave pública RSA como secreto).
2. La firma, con la clave correspondiente al `kid`.
3. `exp` (no caducado) y `nbf` si existe, con un margen pequeño por desfase de relojes.
4. `iss` y `aud`: que lo emitió quien esperas y que va dirigido a este servicio. Sin esta comprobación, un token emitido para otra API del mismo proveedor serviría también en la tuya.
5. Los permisos (`scope`, roles) frente a la operación pedida.

Las buenas prácticas de JWT (RFC 8725) añaden:

- **No seguir claves externas:** ignorar las cabeceras `jku`, `x5u` y `jwk`, que apuntan a una clave elegida por quien envía el token. La clave de verificación sale de tu configuración o del JWKS del emisor que conoces.
- **Tipar los tokens:** RFC 9068 define `typ: at+jwt` para los access tokens. Así una API no acepta por error un ID token de OIDC firmado por el mismo emisor.
- **Claves HMAC largas:** con HS256, al menos 256 bits aleatorios. Una clave como `"secreto"` se rompe por fuerza bruta a partir de un solo token.
- **Unidades:** `exp`, `iat` y `nbf` son segundos desde 1970 (NumericDate), no milisegundos.

#### Access token y refresh token

Como un JWT no se puede revocar fácilmente, se usan dos tokens:

- **Access token:** vida corta (5-15 minutos), se envía en cada petición a la API.
- **Refresh token:** vida larga (días), solo se envía al endpoint de renovación para conseguir un access token nuevo. Es opaco y se guarda en el servidor, así que **sí se puede revocar**.
- **Rotación:** cada vez que se usa un refresh token, se emite uno nuevo y se invalida el anterior. Si alguien intenta reutilizar uno ya usado, es señal de robo: se revoca toda la familia de tokens de esa sesión.

Para revocar un access token antes de que caduque hay dos opciones: una lista negra de `jti` revocados que se consulta en cada petición (reintroduce estado) o, simplemente, aceptar el riesgo durante sus pocos minutos de vida.

#### Dónde guardar los tokens en el navegador

| Lugar | Riesgo XSS | Riesgo CSRF | Comentario |
| --- | --- | --- | --- |
| `localStorage` / `sessionStorage` | Alto: cualquier script lo lee | No | Lo más cómodo y lo más expuesto |
| Variable en memoria (JavaScript) | Medio: un script inyectado puede usarlo mientras la página está abierta | No | Se pierde al recargar; se combina con un refresh token en cookie |
| Cookie `HttpOnly; Secure; SameSite` | Bajo: no se puede leer | Sí, se mitiga con SameSite | Vuelve a ser, en la práctica, una cookie de sesión |

Por eso muchas aplicaciones web usan el patrón **BFF (Backend for Frontend)**: el navegador solo tiene una cookie de sesión `HttpOnly`, y es el backend propio quien guarda los tokens OAuth y llama a las APIs. En apps móviles y de escritorio, los tokens van en el almacén seguro del sistema (Keychain, Keystore, DPAPI).

### OAuth 2.0 y OpenID Connect

OAuth 2.0 (RFC 6749) permite que una aplicación actúe en nombre de un usuario sin conocer su contraseña: el usuario se autentica en un servidor de autorización, que entrega a la aplicación un access token con permisos limitados. OpenID Connect (OIDC) añade encima un **ID token** que dice quién es el usuario, y es lo que hay detrás de "Iniciar sesión con Google" o de Entra ID, Keycloak y Auth0.

#### Roles

- **Propietario del recurso:** el usuario.
- **Cliente:** la aplicación que quiere acceder. Es *confidencial* si puede guardar un secreto (un backend) o *público* si no puede (una SPA, una app móvil).
- **Servidor de autorización (AS):** autentica al usuario y emite los tokens. En OIDC se le llama proveedor de identidad (IdP).
- **Servidor de recursos:** la API que acepta el access token.

#### Flujo authorization code con PKCE

Es el flujo recomendado para cualquier aplicación con usuario, incluidas SPAs y apps móviles. PKCE (RFC 7636) impide que quien intercepte el código de autorización pueda canjearlo.

&#91;embedded content: OAuth 2.0 authorization code con PKCE · 9 mensajes\]

1. **Preparar PKCE:** la aplicación genera un `code_verifier` aleatorio (43-128 caracteres) y calcula `code_challenge = BASE64URL(SHA256(code_verifier))`. Genera también un `state` aleatorio y, con OIDC, un `nonce`.
2. **Redirigir al AS:**

   ```
   GET https://auth.ejemplo.com/authorize?
       response_type=code
       &client_id=mi-app
       &redirect_uri=https://app.ejemplo.com/callback
       &scope=openid profile pedidos:leer
       &state=Xy7...
       &nonce=Qp2...
       &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
       &code_challenge_method=S256
   ```
3. **Login y consentimiento:** el usuario se autentica **en el AS**, no en la aplicación, y acepta los permisos pedidos.
4. **Vuelta con el código:** el AS redirige a `https://app.ejemplo.com/callback?code=SplxlOB...&state=Xy7...`. La aplicación comprueba que `state` es el que generó (protección CSRF del login).
5. **Canje del código (canal trasero):** la aplicación llama directamente al AS:

   ```
   POST /token
   grant_type=authorization_code&code=SplxlOB...
   &redirect_uri=https://app.ejemplo.com/callback
   &client_id=mi-app&code_verifier=dBjftJeZ4CVP...
   ```

   El AS calcula el SHA-256 del `code_verifier` y comprueba que coincide con el `code_challenge` del paso 2. Un cliente confidencial añade además su `client_secret` o se autentica con mTLS o con un JWT firmado.
6. **Tokens:** el AS responde con `access_token`, `refresh_token`, `expires_in` y, con OIDC, `id_token`.
7. **Llamar a la API** con `Authorization: Bearer <access_token>`.

#### El ID token de OpenID Connect

Es un JWT dirigido a la aplicación (no a la API) que describe el login: `sub` (identificador estable del usuario), `iss`, `aud` (el `client_id`), `exp`, `iat`, `nonce`, `auth_time` y datos como `email` o `name` según los scopes. La aplicación debe validarlo como cualquier JWT y comprobar que el `nonce` es el que envió. Para identificar al usuario se usa el par `iss` + `sub`, nunca el email, que puede cambiar.

El AS publica su configuración en `/.well-known/openid-configuration`: endpoints, claves JWKS, scopes y algoritmos soportados.

#### Otros flujos

| Flujo | Para qué | Estado |
| --- | --- | --- |
| Authorization code + PKCE | Apps con usuario: web, SPA, móvil, escritorio | Recomendado |
| Client credentials | Servicio a servicio, sin usuario | Recomendado |
| Device authorization (RFC 8628) | Dispositivos sin teclado: TV, CLI | Recomendado |
| Refresh token | Renovar el access token | Recomendado, con rotación |
| Implicit | SPAs antiguas; el token volvía en la URL | Desaconsejado |
| Resource owner password | La app pide la contraseña al usuario | Desaconsejado |

El documento de buenas prácticas de seguridad de OAuth (RFC 9700) (enero de 2025) y el borrador de OAuth 2.1 (enviado al IESG en julio de 2026, todavía no publicado como RFC) recogen estas recomendaciones: PKCE para todos los clientes, coincidencia exacta de `redirect_uri` y nada de flujos implicit ni password.

#### Precisiones y extensiones de OAuth

- **PKCE y `state`:** el `code_verifier` usa solo caracteres `A-Z a-z 0-9 - . _ ~` y mide entre 43 y 128. El único método aceptable es `S256`; `plain` no protege nada si el atacante ve la petición. Según RFC 9700, un cliente que sabe que el AS aplica PKCE puede confiar en él como protección CSRF; en OIDC, el `nonce` cumple esa función. Aun así, `state` sigue siendo útil para recordar a qué página volver.
- **Mix-up (RFC 9207):** si un cliente trabaja con varios AS, cada respuesta de autorización debe incluir el parámetro `iss`, y el cliente comprueba que coincide con el AS al que envió al usuario.
- **PAR (RFC 9126):** el cliente envía los parámetros de `/authorize` por el canal trasero y recibe un `request_uri`. La URL del navegador ya no muestra ni permite manipular los parámetros.
- **DPoP (RFC 9449):** liga el access token a una clave del cliente. Cada petición lleva una cabecera `DPoP` con un JWT firmado que incluye el método, la URL y la hora. Un token robado no sirve sin la clave privada. Es la alternativa a mTLS (RFC 8705) cuando no se pueden usar certificados de cliente.
- **Metadatos e interoperabilidad:** RFC 8414 (metadatos del AS), RFC 7662 (introspección de tokens opacos), RFC 7009 (revocación), RFC 9068 (access tokens JWT) y RFC 8693 (token exchange, para que un servicio pida un token en nombre de otro).
- **Códigos de autorización:** de un solo uso y de vida corta (como mucho 10 minutos según RFC 6749; en la práctica, unos 60 segundos). Si alguien intenta canjear dos veces el mismo código, el AS debe revocar los tokens que ya emitió con él.

### SAML, API keys y mTLS

#### SAML 2.0

Es el estándar de inicio de sesión único (SSO) más extendido en entornos corporativos, anterior a OIDC y basado en XML. Los papeles son los mismos con otros nombres: el **IdP** (Entra ID, ADFS, Okta) autentica al usuario y el **SP** (*Service Provider*, la aplicación) confía en él.

1. El usuario entra en la aplicación (SP), que lo redirige al IdP con un `AuthnRequest`.
2. El IdP lo autentica, a menudo de forma transparente con Kerberos si está en el dominio de Windows.
3. El IdP devuelve, a través del navegador (un formulario con POST automático), una **aserción SAML**: un XML firmado con el usuario, sus atributos (grupos, email) y su validez.
4. El SP verifica la firma con el certificado del IdP, comprueba `Audience`, `NotOnOrAfter` y `InResponseTo`, y crea su propia sesión con cookie.

La parte delicada es validar la firma XML: los ataques de *XML Signature Wrapping* consiguen que se valide un fragmento firmado mientras la aplicación lee otro inyectado. Por eso hay que usar una librería madura y nunca procesar el XML a mano. Para aplicaciones nuevas suele preferirse OIDC, pero SAML sigue siendo lo habitual al integrarse con directorios corporativos.

#### API keys

Una cadena aleatoria larga que identifica a un **cliente** (un script, otro servicio, un cliente de pago), no a un usuario. Se envía en una cabecera, por ejemplo `X-API-Key` o `Authorization: Bearer`.

- **Genérala** con un generador criptográfico (32 bytes o más) y, a ser posible, con un prefijo reconocible (`sk_live_...`) para que los escáneres de secretos la detecten si se filtra a un repositorio.
- **Guárdala hasheada** (SHA-256 basta, porque es aleatoria y larga, no una contraseña) y muéstrala una sola vez al crearla.
- **Acótala:** permisos mínimos, caducidad, rotación y, si se puede, restricción por IP.
- **Nunca en la URL** (`?api_key=...`): acaba en logs de proxies, en el historial y en la cabecera `Referer`.

#### mTLS: certificados de cliente

En TLS mutuo, el servidor envía `CertificateRequest` durante el handshake y el cliente responde con su certificado y un `CertificateVerify` firmado con su clave privada, como se ve en el diagrama de TLS 1.3. La identidad queda demostrada **antes** de que llegue cualquier petición HTTP, y la credencial no se puede robar copiando una cabecera: hace falta la clave privada.

Se usa entre microservicios (a menudo automático con una *service mesh* como Istio o Linkerd), en APIs bancarias y B2B, en VPNs y en dispositivos IoT. Su coste es gestionar una PKI: emitir, renovar y revocar certificados. Con OpenSSL, el servidor del Anexo B lo activaría con `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL)` y cargando la CA de los clientes; el cliente, cargando su certificado y su clave igual que hace el servidor.

RFC 8705 permite además ligar un access token OAuth al certificado del cliente: aunque roben el token, no sirve sin la clave privada.

### Segundo factor y passkeys

Un segundo factor hace que una contraseña robada no baste. Pero no todos protegen igual: los códigos que el usuario teclea se pueden capturar con una web falsa, y solo WebAuthn (passkeys y llaves de seguridad) es resistente al phishing.

#### TOTP: códigos de 6 dígitos (RFC 6238)

Es lo que generan Google Authenticator, Aegis o Microsoft Authenticator.

1. **Alta:** el servidor genera un secreto aleatorio (normalmente 160 bits), lo guarda asociado al usuario y se lo muestra como QR con una URI `otpauth://totp/MiApp:juan?secret=JBSWY3DPEHPK3PXP&issuer=MiApp`.
2. **Cálculo:** la app y el servidor calculan lo mismo por separado:

   ```
   T      = floor(tiempo_unix / 30)
   HMAC   = HMAC-SHA1(secreto, T como 8 bytes)
   código = truncar(HMAC) mod 10^6
   ```
3. **Verificación:** el servidor acepta el código del intervalo actual y, como mucho, uno antes y uno después por desfase de reloj. Debe recordar el último código usado para que no se pueda reutilizar, y limitar los intentos (con 6 dígitos solo hay un millón de combinaciones).

El secreto TOTP es simétrico: el servidor tiene que guardarlo de forma recuperable, así que va cifrado, no hasheado. Al activar el segundo factor se entregan códigos de recuperación de un solo uso, que sí se guardan hasheados.

#### SMS y notificaciones push

- **SMS:** mejor que nada, pero vulnerable al duplicado de SIM (*SIM swapping*) y a la interceptación de la red móvil. Hoy se desaconseja como único segundo factor.
- **Push:** la app del móvil pregunta "¿eres tú?". Es cómodo, pero sufre la *fatiga de MFA*: el atacante lanza aprobaciones hasta que el usuario acepta una por cansancio. Se mitiga con *number matching*: el usuario teclea en el móvil el número que ve en pantalla.

#### WebAuthn y passkeys

WebAuthn (W3C) junto con CTAP (FIDO2) sustituyen el secreto compartido por **criptografía de clave pública**. El servidor solo guarda la clave pública, así que si roban la base de datos no hay nada que reutilizar. Una *passkey* es una credencial WebAuthn que se sincroniza entre dispositivos (iCloud Keychain, Google Password Manager, gestores como 1Password) y puede sustituir por completo a la contraseña.

**Registro:**

1. El servidor envía un `challenge` aleatorio, su identificador (`rp.id`, por ejemplo `ejemplo.com`) y los datos del usuario.
2. El navegador llama a `navigator.credentials.create()`. El autenticador (Touch ID, Windows Hello, el móvil o una llave YubiKey) pide un gesto al usuario, genera un **par de claves exclusivo para ese sitio** y devuelve la clave pública y un ID de credencial.
3. El servidor guarda la clave pública, el ID de credencial y un contador de firmas.

**Login:**

&#91;embedded content: Login con WebAuthn / passkey\]

1. El servidor envía un `challenge` nuevo.
2. El navegador llama a `navigator.credentials.get()`. El autenticador pide huella, cara o PIN y **firma** el challenge junto con el origen real de la página.
3. El servidor verifica la firma con la clave pública guardada, que el challenge es el suyo, que el origen es el suyo y los flags del autenticador (presencia y, si se exige, verificación del usuario). El contador de firmas solo se comprueba si no es 0: las passkeys sincronizadas de Apple, Google y Microsoft envían siempre 0, así que la detección de clones por contador solo funciona con llaves físicas. Entonces crea la sesión.

**Por qué resiste el phishing:** el navegador incluye en lo firmado el origen real (`https://ejemplo.com`), y el autenticador solo usa la clave asociada a ese `rp.id`. En una web falsa como `ejernplo.com` no hay ninguna credencial que usar, y aunque el atacante reenvíe los mensajes, la firma llevaría el origen equivocado. No hay nada que el usuario pueda teclear por error en la web falsa.

**Qué se firma exactamente:** `firma = Sign(clave_privada, authenticatorData || SHA-256(clientDataJSON))`.

```
clientDataJSON (lo construye el navegador, no la página):
  {"type":"webauthn.get", "challenge":"<base64url>", "origin":"https://ejemplo.com", "crossOrigin":false}

authenticatorData (lo construye el autenticador):
  rpIdHash   32 bytes   SHA-256("ejemplo.com")
  flags       1 byte    UP (presencia), UV (verificación), BE/BS (sincronizable / sincronizada), AT, ED
  signCount   4 bytes   contador (0 en passkeys sincronizadas)
  [datos de la credencial y extensiones, en el registro]
```

El servidor comprueba, en este orden: `type`, que el `challenge` es el que generó (y no se ha usado antes), el `origin`, que `rpIdHash` es el SHA-256 de su `rp.id`, el flag UP, el flag UV si su política lo exige, y la firma con la clave pública guardada. Los algoritmos se identifican con códigos COSE: ES256 (-7), EdDSA (-8) y RS256 (-257). Los flags BE y BS dicen si la credencial puede sincronizarse y si ya lo está, lo que permite, por ejemplo, exigir llaves físicas a las cuentas de administrador.

### Ataques y defensas

| Ataque | En qué consiste | Defensa |
| --- | --- | --- |
| Fuerza bruta y *credential stuffing* | Probar contraseñas o pares filtrados de otros sitios | Límite de intentos, MFA, comprobar contraseñas filtradas, passkeys |
| Phishing | Web falsa que captura contraseña y código OTP | WebAuthn/passkeys; TOTP y SMS no lo impiden |
| Robo de la base de datos | Leer hashes, secretos o tokens guardados | Argon2id con sal, API keys y refresh tokens hasheados, secretos TOTP cifrados |
| XSS | Script inyectado que roba o usa tokens | Escapar la salida, Content-Security-Policy, cookies `HttpOnly`, nada de tokens en `localStorage` |
| CSRF | Otra web provoca peticiones con tus cookies | `SameSite`, token anti-CSRF, comprobar `Origin` |
| Fijación de sesión | La víctima usa un ID que conoce el atacante | Regenerar el ID de sesión al autenticar |
| Robo de cookie o token | Copiar la credencial bearer | HTTPS y HSTS, vida corta, rotación de refresh tokens, mTLS o DPoP |
| Manipulación de JWT | `alg: none`, confusión de algoritmos, `kid` malicioso | Fijar el algoritmo, validar `iss`, `aud` y `exp`, librería mantenida |
| Robo del código OAuth | Interceptar la redirección con el `code` | PKCE, `redirect_uri` exacta, `state` |
| Open redirect | Redirigir tras el login a un dominio del atacante | Lista blanca de destinos de redirección |
| Enumeración de usuarios | Mensajes o tiempos distintos si el usuario existe | Mismo mensaje y mismo tiempo de respuesta en todos los casos |
| Fatiga de MFA | Bombardear con notificaciones push | *Number matching*, límite de solicitudes |

### Qué mecanismo usar en cada caso

| Escenario | Recomendación |
| --- | --- |
| Aplicación web clásica renderizada en servidor | Sesión con cookie `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax` |
| SPA (React, Vue...) con su propio backend | Patrón BFF: cookie de sesión en el navegador y tokens solo en el backend |
| App móvil o de escritorio | OAuth authorization code + PKCE con el navegador del sistema; tokens en el almacén seguro |
| "Iniciar sesión con..." o SSO | OpenID Connect; SAML si lo exige el directorio corporativo |
| API pública para terceros | OAuth 2.0 (client credentials o authorization code) o API keys acotadas |
| Microservicios internos | mTLS, o client credentials con JWT de vida corta |
| Scripts y herramientas internas | API key o HTTP Basic, siempre sobre HTTPS |
| Login de usuarios en general | Passkeys como objetivo; si hay contraseña, Argon2id y un segundo factor |

## Ataques frecuentes y cómo evitarlos

Hoy casi ningún ataque rompe la criptografía de TLS. Los que funcionan rodean el cifrado: engañan al usuario para que entregue sus credenciales, roban la sesión ya autenticada o aprovechan que el servidor no comprueba bien quién puede hacer qué. Esta sección recorre los ataques más habituales por capas, con cómo funcionan, casos reales y la configuración concreta para evitarlos.

| Capa | Ataques más frecuentes | Defensa principal |
| --- | --- | --- |
| Transporte | SSL stripping, certificados fraudulentos, versiones y cifrados antiguos | HSTS con preload, TLS 1.2+ con AEAD, CAA y vigilancia de Certificate Transparency |
| Credenciales | Credential stuffing, phishing con proxy (AiTM), fatiga de MFA, SIM swapping | Passkeys, límite de intentos, contraseñas filtradas bloqueadas |
| Sesión | Robo de cookies por malware, XSS, CSRF, clickjacking | Cookies `HttpOnly` + `SameSite`, CSP, sesiones ligadas al dispositivo |
| Tokens y OAuth | Confusión de algoritmos JWT, fugas de tokens, open redirect, phishing de consentimiento | Validación estricta, PKCE, `redirect_uri` exacta, vida corta |
| Servidor | IDOR, SSRF, inyección SQL | Autorización en cada petición, listas blancas de destinos, consultas parametrizadas |

La clasificación OWASP Top 10:2025, la referencia habitual en seguridad web, sigue poniendo en primer lugar el **control de acceso roto** (A01), que ahora incluye el SSRF. Le siguen la configuración insegura (A02) y los fallos de la cadena de suministro de software (A03). Los fallos de autenticación son la A07 y los criptográficos la A04.

### Ataques al transporte

#### SSL stripping

**Cómo funciona:** el usuario escribe `ejemplo.com` y el navegador empieza por `http://`. Un atacante en la misma red (una wifi pública, un router comprometido) intercepta esa primera petición en claro, habla HTTPS con el servidor real y sirve al usuario la web en HTTP. El usuario ve la página de siempre, sin candado, y envía su contraseña en claro al atacante.

**Cómo evitarlo:**

- Redirigir todo el HTTP a HTTPS con un 301.
- Enviar **HSTS**: el navegador recuerda que ese dominio solo se usa con HTTPS y no vuelve a intentar HTTP durante `max-age` segundos.

  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```
- Para proteger también la **primera** visita, inscribir el dominio en la lista de precarga de HSTS (hstspreload.org), que viene incluida en los navegadores. Requisitos: `max-age` de al menos un año, `includeSubDomains`, la directiva `preload` y todos los subdominios en HTTPS. Salir de la lista tarda meses, así que hay que estar seguro antes de inscribirse.

#### Certificados fraudulentos y CAs comprometidas

**Cómo funciona:** si un atacante consigue un certificado válido para tu dominio, sea por una CA comprometida, por un fallo en su validación o por un DNS secuestrado, puede suplantar el sitio sin que el navegador avise. Ha pasado: DigiNotar (2011) emitió certificados falsos de Google usados para espiar a usuarios en Irán, y la CA quebró.

**Cómo evitarlo:**

- **Registro DNS CAA** (RFC 8659): indica qué CAs pueden emitir certificados para tu dominio. Las CAs están obligadas a respetarlo.

  ```
  ejemplo.com.  CAA 0 issue "letsencrypt.org"
  ejemplo.com.  CAA 0 issuewild ";"
  ejemplo.com.  CAA 0 iodef "mailto:seguridad@ejemplo.com"
  ```
- **Vigilar Certificate Transparency:** como todo certificado público tiene que aparecer en los logs de CT, puedes recibir avisos de cualquier certificado emitido para tu dominio (crt.sh, Cert Spotter, el monitor de Cloudflare o de Facebook).
- **DNSSEC y bloqueo del registrador:** si el atacante controla tu DNS, puede superar la validación de dominio de cualquier CA. Protege la cuenta del registrador con MFA fuerte y activa el bloqueo de transferencias.
- **No usar *certificate pinning* en webs:** fijar claves concretas en el cliente se abandonó en navegadores (HPKP) porque bloqueaba sitios enteros por error. Solo tiene sentido en apps propias, y con cuidado ahora que los certificados duran pocas semanas.

#### Ataques históricos a TLS y SSL

Casi todos estos ataques están resueltos en TLS 1.3, pero reaparecen en servidores que mantienen configuraciones antiguas por compatibilidad:

| Ataque | Año | Qué explotaba | Si sigue siendo un riesgo, qué lo evita |
| --- | --- | --- | --- |
| BEAST | 2011 | IV predecible de CBC en TLS 1.0 | Desactivar TLS 1.0 y 1.1 |
| CRIME | 2012 | Compresión a nivel TLS: el tamaño filtra secretos | Compresión TLS desactivada (eliminada en 1.3) |
| BREACH | 2013 | La misma idea con compresión HTTP (gzip) | No comprimir respuestas que mezclen secretos y datos del usuario; tokens CSRF enmascarados en cada respuesta |
| Lucky13 | 2013 | Diferencias de tiempo al comprobar el MAC en CBC | Solo suites AEAD |
| Heartbleed (CVE-2014-0160) | 2014 | Fallo de OpenSSL 1.0.1-1.0.1f que dejaba leer 64 KB de memoria del servidor, incluidas claves privadas | Mantener OpenSSL actualizado; tras un fallo así, revocar y renovar certificados |
| POODLE (CVE-2014-3566) | 2014 | Relleno de CBC en SSL 3.0 | SSL 3.0 desactivado |
| FREAK y Logjam | 2015 | Suites "de exportación" de 512 bits (RSA y DH) | Sin suites de exportación; DH de al menos 2048 bits |
| Sweet32 | 2016 | Colisiones en cifrados de bloque de 64 bits (3DES) | Sin 3DES |
| ROBOT | 2017 | Oráculo de Bleichenbacher en el intercambio RSA | Sin intercambio RSA; solo ECDHE |

**Cómo evitarlo de una vez:** ofrecer solo TLS 1.2 (con ECDHE y AEAD) y TLS 1.3, mantener la librería TLS al día y comprobarlo con `testssl.sh` o con el test de SSL Labs tras cada cambio de configuración.

### Robo y abuso de credenciales

#### Credential stuffing y password spraying

**Cómo funcionan:** en el *credential stuffing*, el atacante prueba pares usuario/contraseña filtrados de otros sitios, porque mucha gente repite contraseñas; en el *password spraying*, prueba unas pocas contraseñas comunes (`Verano2026!`) contra muchas cuentas, para no disparar el bloqueo por cuenta. Los dos usan botnets con miles de IPs residenciales, así que limitar por IP no basta.

**Cómo detectarlo:** muchos fallos de login repartidos entre muchas cuentas, ratio de éxito anormalmente bajo, picos desde rangos de IPs nuevos o con agentes de usuario repetidos.

**Cómo evitarlo:**

- Limitar intentos **por cuenta y por IP**, con retrasos crecientes en vez de bloqueos permanentes, que un atacante usaría para bloquear cuentas ajenas.
- Rechazar contraseñas que aparecen en filtraciones. El servicio Pwned Passwords permite comprobarlo sin revelar la contraseña: se envían solo los 5 primeros caracteres hexadecimales de su SHA-1 y se recibe la lista de sufijos que coinciden (*k-anonimato*).

  ```bash
  h=$(printf '%s' 'Verano2026!' | sha1sum | tr a-f A-F | cut -c1-40)
  curl -s "https://api.pwnedpasswords.com/range/${h:0:5}" | grep "${h:5}"
  ```
- MFA o, mejor, passkeys, que eliminan el problema porque no hay contraseña que reutilizar.
- Un CAPTCHA o un desafío de prueba de trabajo solo cuando el riesgo es alto, no en cada login.

#### Phishing con proxy intermedio (AiTM)

Es la forma actual del phishing, y la razón por la que TOTP, SMS y notificaciones push ya no bastan. En vez de una copia estática de la web, el atacante pone un **proxy inverso** entre la víctima y el sitio real (con herramientas públicas como Evilginx). La víctima ve la web auténtica, completa el login con su segundo factor, y el proxy se queda con la cookie de sesión que devuelve el sitio real. Microsoft documentó en 2022 una campaña AiTM contra más de 10.000 organizaciones.

&#91;embedded content: Phishing AiTM · el proxy captura la sesión tras el segundo factor\]

**Cómo evitarlo:**

- **Passkeys o llaves FIDO2:** son la única defensa completa. El navegador firma el origen real (`https://login-ejemplo.com`), el autenticador no tiene credencial para ese dominio y, aunque el proxy reenviara la firma, el servidor vería un origen que no es el suyo.
- **Sesiones ligadas al dispositivo:** con DBSC o tokens ligados, la cookie robada no sirve desde otro equipo.
- **Acceso condicional:** pedir que el login venga de dispositivos gestionados o de ubicaciones conocidas, y alertar de sesiones que cambian de país o de huella de dispositivo poco después del login.
- **Dominios propios reconocibles:** usar siempre el mismo dominio de login y enseñar a los usuarios a comprobarlo, aunque por sí solo no basta.

#### Fatiga de MFA y SIM swapping

- **Fatiga de MFA:** con la contraseña ya robada, el atacante lanza aprobaciones push sin parar, a menudo de madrugada, hasta que el usuario acepta una para que paren. Así entró el atacante en Uber en 2022, combinándolo con un mensaje que fingía venir del soporte informático. Se evita con *number matching* (el usuario teclea el número que ve en pantalla), mostrando la ubicación de la petición, limitando las solicitudes y avisando al equipo de seguridad cuando alguien las rechaza.
- **SIM swapping:** el atacante convence a la operadora de que le duplique la SIM de la víctima y recibe sus SMS. No hay defensa técnica dentro de la aplicación: la solución es no usar SMS como factor para cuentas importantes y no permitir recuperar la cuenta solo con un SMS.

#### Recuperación de contraseña

Es la puerta trasera de cualquier login, y a menudo la más débil:

- **Token del enlace:** al menos 128 bits aleatorios, de un solo uso, con caducidad corta (15-60 minutos) y guardado hasheado, igual que una contraseña.
- **Envenenamiento de la cabecera Host:** si el servidor construye el enlace del correo con la cabecera `Host` de la petición, un atacante pide la recuperación con `Host: atacante.com` y la víctima recibe un enlace, auténtico, que envía su token al atacante. El enlace debe construirse siempre con la URL base de la configuración.
- **Misma respuesta siempre:** "si la cuenta existe, recibirás un correo", para no revelar qué correos están registrados.
- **Después del cambio:** cerrar todas las sesiones y revocar los refresh tokens, y avisar al usuario por correo.

### Secuestro de sesión

#### Robo de cookies por malware (infostealers)

**Cómo funciona:** un malware de tipo *infostealer* (RedLine, Lumma y similares, que suelen llegar con programas pirateados o extensiones falsas) copia las cookies del perfil del navegador y las vende. El comprador las importa en su navegador y entra en la cuenta ya autenticada, sin contraseña ni segundo factor (*pass-the-cookie*). `HttpOnly` no ayuda aquí: protege frente a JavaScript, no frente a un programa que lee el disco.

**Cómo evitarlo:**

- **Sesiones ligadas al dispositivo (DBSC):** el navegador genera una clave en el TPM del equipo, que no se puede exportar, y el servidor emite cookies de vida muy corta que solo se renuevan si el navegador demuestra tener esa clave. Una cookie robada caduca en minutos y no se puede renovar desde otro equipo. Chrome lo ofrece de forma general desde la versión 146 en Windows (abril de 2026), con macOS en camino. El servidor tiene que implementar los endpoints de registro y renovación.
- **Señales de riesgo:** invalidar la sesión si cambian bruscamente la IP, el país, el sistema operativo o la huella TLS del cliente, y pedir de nuevo el login antes de acciones sensibles (cambiar el correo, añadir un método de pago, crear claves de API).
- **Vida corta y revocación:** caducidad por inactividad y absoluta, y un botón de "cerrar todas las sesiones" que de verdad borre las sesiones en el servidor.

#### XSS (Cross-Site Scripting)

**Cómo funciona:** la aplicación inserta en la página un dato del usuario sin escaparlo, por ejemplo un comentario con `<script>`. El script se ejecuta con el origen de tu web, así que puede leer `localStorage`, llamar a tu API con las cookies del usuario o cambiar el formulario de login para enviar la contraseña a otro sitio.

**Cómo evitarlo:**

- **Escapar por contexto:** usar el motor de plantillas del framework (Jinja2, React, Razor), que escapa por defecto, y no saltarse ese escape (`|safe`, `dangerouslySetInnerHTML`, `innerHTML`) con datos del usuario.
- **Content-Security-Policy con nonces:** el navegador solo ejecuta los scripts que llevan el nonce aleatorio de esa respuesta. Un script inyectado no lo conoce.

  ```
  Content-Security-Policy: default-src 'self'; script-src 'nonce-R4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
  ```
- **No guardar tokens donde JavaScript los lea**, y cookies de sesión con `HttpOnly`.
- **Trusted Types** (en navegadores Chromium) bloquea la asignación de cadenas a `innerHTML` y similares si no pasan por una función de saneado.

#### CSRF

Está explicado en la sección de sesiones. Resumen de defensas, de más a menos importante: `SameSite=Lax` o `Strict` en la cookie de sesión, rechazar peticiones que cambian estado con un `Origin` o un `Sec-Fetch-Site: cross-site` ajeno, y un token anti-CSRF en los formularios. Nunca cambiar estado con peticiones GET.

#### Clickjacking

**Cómo funciona:** una web maliciosa carga la tuya en un iframe transparente encima de un botón señuelo. El usuario cree que pulsa "ver vídeo" y en realidad pulsa "autorizar aplicación" o "borrar cuenta" en tu web, con su sesión.

**Cómo evitarlo:** impedir que la web se cargue en iframes de otros sitios con `Content-Security-Policy: frame-ancestors 'self'` (o `'none'`). La cabecera antigua `X-Frame-Options: DENY` se mantiene para navegadores viejos. Las pantallas de consentimiento OAuth y de pago deben llevarla siempre.

### Ataques a tokens y OAuth

#### Confusión de algoritmos en JWT

**Cómo funciona:** la API firma con RS256 y verifica con su clave pública, que es pública por definición. El atacante crea un token con `"alg": "HS256"` y lo firma con HMAC usando esa **clave pública** como secreto. Si el servidor deja que la cabecera elija el algoritmo, verificará un HMAC con la misma clave pública y el token falso será válido. La variante `"alg": "none"` es todavía más simple: un token sin firma.

```python
# VULNERABLE: el token decide cómo se verifica
alg = jwt.get_unverified_header(token)["alg"]
claims = jwt.decode(token, CLAVE_PUBLICA_PEM, algorithms=[alg])

# CORRECTO: el algoritmo lo fija el servidor, y se validan emisor y audiencia
claims = jwt.decode(token, CLAVE_PUBLICA_PEM, algorithms=["RS256"],
                    audience="https://api.ejemplo.com", issuer="https://auth.ejemplo.com")
```

Probado con PyJWT 2.15: con un token HS256 firmado con la clave pública, la versión correcta lo rechaza con `InvalidAlgorithmError`. PyJWT 2.x tiene además una segunda barrera: se niega a usar una clave PEM como secreto HMAC (`InvalidKeyError`). Otras librerías, y las versiones antiguas, no la tienen, así que la defensa real es fijar el algoritmo.

**Otros fallos de JWT frecuentes:** secretos HS256 débiles que se rompen con hashcat a partir de un solo token, no comprobar `exp` o `aud`, y aceptar claves de las cabeceras `jku`, `x5u` o `jwk`.

#### Fugas de tokens

Un token *bearer* filtrado es una sesión robada. Las fugas más habituales:

- **En la URL:** `?access_token=...` acaba en el historial, en los logs del servidor y del proxy, y en la cabecera `Referer` hacia otros sitios. Los tokens van siempre en la cabecera `Authorization`. Si un flujo obliga a ponerlos en la URL, hay que añadir `Referrer-Policy: no-referrer`.
- **En los logs:** registrar cabeceras completas, cuerpos de peticiones o URLs con tokens. Hay que filtrar `Authorization`, `Cookie` y parámetros como `code`, `token` o `password` antes de escribir el log.
- **En el código:** claves de API en repositorios, imágenes Docker o aplicaciones móviles. Se evita con escáneres de secretos en el CI y en el repositorio (GitHub Secret Scanning, gitleaks) y con rotación inmediata cuando aparece una.

#### Open redirect y manipulación de redirect\_uri

**Cómo funciona:** tu web tiene `/salir?next=https://...` y redirige a cualquier sitio. El atacante lo usa para que un enlace de phishing empiece por tu dominio. Y si el servidor de autorización acepta `redirect_uri` por prefijo o con comodines, el atacante registra o consigue una URL válida que acaba enviando el código de autorización a su servidor.

**Cómo evitarlo:** redirigir solo a rutas relativas o a una lista blanca de destinos; en OAuth, comparación **exacta** de `redirect_uri` con las registradas (RFC 9700), y PKCE, que hace inútil un código robado.

#### Phishing de consentimiento (illicit consent grant)

**Cómo funciona:** el atacante registra una aplicación OAuth con un nombre creíble ("Visor de PDF") en Microsoft 365 o Google Workspace y envía a la víctima el enlace de autorización **legítimo** del proveedor. La víctima inicia sesión en la web real, con su MFA, y concede permisos como `Mail.Read` u `offline_access`. El atacante obtiene un refresh token que sobrevive a los cambios de contraseña.

**Cómo evitarlo:** impedir que los usuarios concedan permisos a aplicaciones no verificadas (o exigir aprobación de un administrador), revisar periódicamente las aplicaciones autorizadas en el tenant y revocar sus tokens si son sospechosas.

### Ataques al servidor

#### Control de acceso roto e IDOR

Es la categoría número uno de OWASP. El usuario está bien autenticado, pero el servidor no comprueba si **ese** usuario puede acceder a **ese** recurso. El caso típico es el IDOR (*Insecure Direct Object Reference*): cambiar `/api/facturas/1041` por `/api/facturas/1042` y ver la factura de otro cliente.

```python
# VULNERABLE: comprueba que hay sesión, pero no de quién es la factura
@app.get("/api/facturas/<int:id>")
@requiere_sesion
def factura(id):
    return jsonify(db.factura(id))

# CORRECTO: la consulta se limita a los recursos del usuario autenticado
@app.get("/api/facturas/<int:id>")
@requiere_sesion
def factura(id):
    f = db.factura(id, propietario=g.usuario)
    if f is None:
        return jsonify(error="no encontrada"), 404   # 404 y no 403: no revela que existe
    return jsonify(f)
```

**Cómo evitarlo:** denegar por defecto, comprobar la autorización en el servidor en **cada** petición (nunca fiarse de que el botón esté oculto en la interfaz), filtrar las consultas por propietario o tenant, y añadir tests automatizados que intenten acceder con un usuario a los recursos de otro. Los identificadores aleatorios (UUID) dificultan adivinar, pero no sustituyen la comprobación.

#### SSRF (Server-Side Request Forgery)

**Cómo funciona:** la aplicación descarga una URL que le da el usuario (una imagen de perfil, una vista previa de un enlace, un webhook). El atacante le da una URL interna: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, el servicio de metadatos de la nube, que devuelve credenciales temporales del servidor. Así se produjo la filtración de Capital One en 2019, con datos de unos 100 millones de clientes. Otros objetivos habituales son paneles de administración en `localhost`, Redis, o servicios de la red interna.

**Cómo evitarlo:**

- **Lista blanca** de dominios o, si no es posible, resolver el nombre y rechazar direcciones privadas, de loopback, link-local (`169.254.0.0/16`), `fd00::/8` y similares.
- **Validar la IP con la que de verdad se conecta**, no solo la que resolvió antes: si no, un *DNS rebinding* devuelve una IP pública al validar y una interna al conectar. También hay que desactivar las redirecciones automáticas o validar cada salto.
- **En la nube, IMDSv2** (AWS) o su equivalente: el servicio de metadatos exige un token obtenido con un PUT y un límite de saltos de 1, lo que bloquea casi todos los SSRF simples.
- Hacer las descargas desde un servicio aislado sin acceso a la red interna, y dar a las credenciales del servidor los permisos mínimos.

#### Inyección SQL en el login

**Cómo funciona:** la consulta se construye pegando texto del usuario. Con el nombre `x' OR '1'='1' --`, la condición siempre es cierta y la consulta devuelve el primer usuario de la tabla, que suele ser el administrador.

```python
nombre = "x' OR '1'='1' --"

# VULNERABLE: concatenar
db.execute(f"SELECT nombre FROM usuarios WHERE nombre = '{nombre}'").fetchone()
# -> ('admin',)

# CORRECTO: consulta parametrizada; el dato nunca se interpreta como SQL
db.execute("SELECT nombre FROM usuarios WHERE nombre = ?", (nombre,)).fetchone()
# -> None
```

Los dos resultados son reales, ejecutados con SQLite. **Cómo evitarlo:** usar siempre consultas parametrizadas o un ORM, sin construir SQL con cadenas; la cuenta de base de datos de la aplicación con los permisos mínimos; y, en el login, recuperar el usuario por nombre y verificar el hash en el código, nunca con `WHERE password = ...`.

### Lista de comprobación de endurecimiento

#### Configuración de nginx

Esta configuración reúne las defensas de transporte y de navegador de esta sección. Está probada con nginx 1.24 (el de Ubuntu 24.04): `nginx -t` la acepta, la redirección va al dominio configurado y las seis cabeceras llegan incluso en las respuestas de error.

```nginx
server {
    listen 80;
    server_name ejemplo.com;
    # Dominio fijo: no se construye la URL con la cabecera Host del cliente
    return 301 https://ejemplo.com$request_uri;
}

server {
    listen 443 ssl http2;        # nginx 1.25.1 o posterior: "listen 443 ssl;" y "http2 on;"
    server_name ejemplo.com;

    ssl_certificate     /etc/letsencrypt/live/ejemplo.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ejemplo.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;     # en TLS 1.2, una clave de tickets que no rota rompe el forward secrecy
    server_tokens off;           # no anunciar la versión de nginx

    # "always": también en respuestas de error (4xx, 5xx)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
```

Dos avisos sobre nginx: `add_header` dentro de un bloque `location` **anula** todas las cabeceras heredadas del `server`, así que hay que repetirlas o moverlas a un fichero común con `include`. Y la CSP de ejemplo es estricta: con scripts o estilos en línea, la web dejará de funcionar hasta añadir nonces. Conviene empezar con `Content-Security-Policy-Report-Only` para ver qué se rompería.

#### Tareas

**Transporte**

- [ ] Solo TLS 1.2 y 1.3; en 1.2, solo ECDHE con AEAD
- [ ] HTTP redirige a HTTPS y se envía HSTS con `max-age` de al menos un año
- [ ] Dominio inscrito en la lista de precarga de HSTS (si todos los subdominios usan HTTPS)
- [ ] Registro DNS CAA con las CAs autorizadas
- [ ] Avisos de Certificate Transparency para el dominio
- [ ] Renovación automática de certificados con ACME, preparada para validez de 47 días
- [ ] `testssl.sh` o SSL Labs sin avisos tras cada cambio

**Credenciales y sesión**

- [ ] Contraseñas con Argon2id (o bcrypt) y parámetros de OWASP
- [ ] Límite de intentos por cuenta y por IP
- [ ] Contraseñas filtradas rechazadas al registrarse y al cambiarlas
- [ ] Passkeys disponibles; obligatorias para administradores
- [ ] Sin SMS como único segundo factor; *number matching* en push
- [ ] Cookie de sesión `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` y regenerada al autenticar
- [ ] Caducidad por inactividad y absoluta; logout que borra la sesión en el servidor
- [ ] Recuperación de contraseña con token aleatorio de un uso, URL base fija y cierre de sesiones

**Tokens y OAuth**

- [ ] Algoritmo de JWT fijado en el servidor; `iss`, `aud` y `exp` validados
- [ ] Access tokens de 15 minutos o menos; refresh tokens rotatorios con detección de reutilización
- [ ] Tokens fuera de URLs y logs; escáner de secretos en el repositorio
- [ ] PKCE S256 y `redirect_uri` exacta en todos los clientes OAuth
- [ ] Consentimiento de aplicaciones de terceros restringido en el tenant

**Aplicación**

- [ ] Autorización comprobada en cada endpoint, con tests de acceso cruzado entre usuarios
- [ ] Consultas parametrizadas en todo el código
- [ ] Descargas de URLs con lista blanca y sin acceso a la red interna; IMDSv2 en la nube
- [ ] CSP con nonces, `frame-ancestors` y el resto de cabeceras de seguridad
- [ ] Logs de autenticación (éxitos, fallos, cambios de MFA) con alertas, sin datos sensibles

## Referencias

Especificaciones en las que se basa este documento, y fuentes de los datos que cambian con el tiempo (consultadas en noviembre de 2026).

**TLS y certificados**

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) · [RFC 9001 — TLS en QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 5746 — renegotiation\_info](https://www.rfc-editor.org/rfc/rfc5746) · [RFC 7627 — Extended Master Secret](https://www.rfc-editor.org/rfc/rfc7627) · [RFC 7366 — Encrypt-then-MAC](https://www.rfc-editor.org/rfc/rfc7366) · [RFC 7905 — ChaCha20-Poly1305 en TLS](https://www.rfc-editor.org/rfc/rfc7905)
- [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/info/rfc9849) (noviembre de 2025) · [RFC 9266 — channel binding tls-exporter](https://www.rfc-editor.org/rfc/rfc9266)
- [RFC 5280 — perfil de certificados X.509](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 9525 — verificación del nombre del servicio](https://www.rfc-editor.org/rfc/rfc9525) · [RFC 8555 — ACME](https://www.rfc-editor.org/rfc/rfc8555) · [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- Intercambio híbrido post-cuántico: [lista de soporte de X25519MLKEM768 en la documentación de Cloudflare](https://github.com/cloudflare/cloudflare-docs/pull/26233.diff)
- Validez de certificados: [votación SC-081v3 del CA/Browser Forum, resumida por DNSimple](https://support.dnsimple.com/articles/announcement-ssl-certificate-validity-changes/)
- OCSP: [Let's Encrypt, "Ending OCSP Support in 2025"](https://letsencrypt.org/2024/12/05/ending-ocsp/) y [anuncio del apagado](https://community.letsencrypt.org/t/ending-ocsp-support-in-2025/229786)

**Autenticación web**

- [RFC 7617 — HTTP Basic](https://www.rfc-editor.org/rfc/rfc7617) · [RFC 7616 — HTTP Digest](https://www.rfc-editor.org/rfc/rfc7616) · [RFC 6265 — cookies](https://www.rfc-editor.org/rfc/rfc6265)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106) · [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519) · [RFC 8725 — buenas prácticas de JWT](https://www.rfc-editor.org/rfc/rfc8725) · [RFC 9068 — access tokens JWT](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) · [RFC 6750 — Bearer](https://www.rfc-editor.org/rfc/rfc6750) · [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636) · [RFC 9700 — buenas prácticas de seguridad de OAuth](https://www.rfc-editor.org/rfc/rfc9700.html) · [borrador de OAuth 2.1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [RFC 9207 — parámetro iss](https://www.rfc-editor.org/rfc/rfc9207) · [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126) · [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449) · [RFC 8705 — OAuth con mTLS](https://www.rfc-editor.org/rfc/rfc8705) · [RFC 8628 — device flow](https://www.rfc-editor.org/rfc/rfc8628)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 4226 — HOTP](https://www.rfc-editor.org/rfc/rfc4226) · [RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238)
- [W3C Web Authentication](https://www.w3.org/TR/webauthn-2/) · contador de firmas en passkeys: [MojoAuth, "signCount Is Dead"](https://mojoauth.com/blog/signcount-is-dead-why-passkey-clone-detection-doesnt-work-anymore)

**Ataques y defensas**

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/it/) · [RFC 8659 — registros DNS CAA](https://www.rfc-editor.org/rfc/rfc8659) · [RFC 6797 — HSTS](https://www.rfc-editor.org/rfc/rfc6797) · [lista de precarga de HSTS](https://hstspreload.org/)
- [Google, "Protecting Cookies with Device Bound Session Credentials"](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/) (abril de 2026)
- [Pwned Passwords — API por rangos](https://haveibeenpwned.com/API/v3#PwnedPasswords)

## Anexo A: abreviaturas

| Abreviatura | Significado | Qué es |
| --- | --- | --- |
| 0-RTT | Zero Round-Trip Time | Enviar datos en el primer vuelo, sin esperar respuesta |
| 3DES | Triple Data Encryption Standard | Cifrado por bloques antiguo, eliminado en TLS 1.3 |
| AAD | Additional Authenticated Data | Datos que no se cifran pero sí se autentican (la cabecera del registro) |
| ACME | Automatic Certificate Management Environment | Protocolo para pedir y renovar certificados automáticamente (RFC 8555) |
| AEAD | Authenticated Encryption with Associated Data | Cifrado que protege confidencialidad e integridad a la vez |
| AES | Advanced Encryption Standard | Cifrado simétrico por bloques estándar |
| ALPN | Application-Layer Protocol Negotiation | Extensión que negocia el protocolo de aplicación (h2, http/1.1) |
| BFF | Backend for Frontend | Backend propio que guarda los tokens; el navegador solo tiene una cookie de sesión |
| CA | Certificate Authority | Autoridad que firma certificados |
| CBC | Cipher Block Chaining | Modo de cifrado por bloques, vulnerable en TLS (Lucky13, POODLE) |
| CCM | Counter with CBC-MAC | Modo AEAD de AES, usado sobre todo en dispositivos pequeños |
| CCS | ChangeCipherSpec | Registro de TLS 1.2 que indica "a partir de aquí, cifro" |
| ChaCha20-Poly1305 | Cifrado ChaCha20 + MAC Poly1305 | AEAD rápido sin aceleración por hardware |
| CRL | Certificate Revocation List | Lista firmada de certificados revocados que publica la CA |
| CSRF | Cross-Site Request Forgery | Otra web hace que el navegador envíe peticiones con tus cookies |
| CT | Certificate Transparency | Registros públicos de todos los certificados emitidos |
| DH / DHE | Diffie-Hellman / Diffie-Hellman Ephemeral | Acuerdo de clave; la E indica claves de un solo uso |
| DNS | Domain Name System | Resolución de nombres de dominio a IPs |
| DoH / DoT | DNS over HTTPS / DNS over TLS | DNS cifrado |
| DPoP | Demonstrating Proof of Possession | Liga un token OAuth a una clave del cliente (RFC 9449) |
| ECDHE | Elliptic Curve Diffie-Hellman Ephemeral | Diffie-Hellman sobre curvas elípticas con claves efímeras |
| ECH | Encrypted Client Hello | Extensión que cifra el ClientHello, incluido el SNI |
| GCM | Galois/Counter Mode | Modo AEAD de AES |
| HKDF | HMAC-based Key Derivation Function | Función de derivación de claves de TLS 1.3 (Extract + Expand) |
| HMAC | Hash-based Message Authentication Code | MAC construido sobre una función hash |
| HPKE | Hybrid Public Key Encryption | Cifrado de clave pública híbrido que usa ECH (RFC 9180) |
| HRR | HelloRetryRequest | Respuesta de TLS 1.3 que pide otro key\_share |
| HSM | Hardware Security Module | Dispositivo que guarda claves y firma sin dejarlas salir |
| HSTS | HTTP Strict Transport Security | Cabecera que obliga al navegador a usar siempre HTTPS |
| HTTP / HTTPS | Hypertext Transfer Protocol (Secure) | Protocolo web; HTTPS es HTTP sobre TLS |
| IdP | Identity Provider | Proveedor de identidad que autentica al usuario en SSO (OIDC o SAML) |
| IV | Initialization Vector | Valor inicial que hace único cada cifrado |
| JWKS | JSON Web Key Set | Conjunto de claves públicas que publica un emisor de JWT |
| JWT | JSON Web Token | Token firmado con cabecera, carga y firma en base64url (RFC 7519) |
| KEM | Key Encapsulation Mechanism | Mecanismo para acordar un secreto cifrándolo con una clave pública |
| MAC | Message Authentication Code | Código que prueba integridad y origen de un mensaje |
| MFA | Multi-Factor Authentication | Autenticación con al menos dos factores distintos |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism | Intercambio de claves post-cuántico (antes Kyber) |
| mTLS | Mutual TLS | TLS en el que el cliente también presenta certificado |
| OAuth | Open Authorization | Protocolo de autorización delegada (RFC 6749) |
| OCSP | Online Certificate Status Protocol | Consulta de si un certificado está revocado |
| OIDC | OpenID Connect | Capa de identidad sobre OAuth 2.0; añade el ID token |
| PAR | Pushed Authorization Requests | Enviar los parámetros de /authorize por el canal trasero (RFC 9126) |
| PKCE | Proof Key for Code Exchange | Protege el código de autorización de OAuth (RFC 7636) |
| PKCS#1 | Public-Key Cryptography Standards #1 | Estándar de RSA; su firma v1.5 no vale para CertificateVerify en 1.3, aunque sí para firmar certificados |
| PKI | Public Key Infrastructure | Conjunto de CAs, certificados y políticas para gestionar claves públicas |
| POODLE | Padding Oracle On Downgraded Legacy Encryption | Ataque contra CBC en SSL 3.0 |
| PRF | Pseudo-Random Function | Función de derivación de claves de TLS 1.2 |
| PSK | Pre-Shared Key | Clave compartida previa; en 1.3, la que sale de un ticket |
| QUIC | QUIC (nombre propio) | Transporte sobre UDP con TLS 1.3 integrado; base de HTTP/3 |
| RC4 | Rivest Cipher 4 | Cifrado de flujo roto, prohibido en TLS |
| RFC | Request for Comments | Documentos que definen los estándares de Internet |
| RSA | Rivest-Shamir-Adleman | Algoritmo de clave pública para firma y cifrado |
| RSA-PSS | RSA Probabilistic Signature Scheme | Esquema de firma RSA obligatorio en CertificateVerify de TLS 1.3 |
| RTT | Round-Trip Time | Un viaje de ida y vuelta entre cliente y servidor |
| SAML | Security Assertion Markup Language | Estándar XML de inicio de sesión único corporativo |
| SAN | Subject Alternative Name | Campo del certificado con los dominios que cubre |
| SCT | Signed Certificate Timestamp | Prueba firmada de que un certificado está en un log de CT |
| SHA-256 | Secure Hash Algorithm, 256 bits | Función hash usada en derivación y firmas |
| SNI | Server Name Indication | Extensión con el dominio al que se conecta el cliente |
| SP | Service Provider | En SAML, la aplicación que confía en el IdP |
| SSL | Secure Sockets Layer | Predecesor de TLS, obsoleto |
| SSO | Single Sign-On | Iniciar sesión una vez y acceder a varias aplicaciones |
| SVCB / HTTPS RR | Service Binding | Registros DNS que publican parámetros del servicio, como la clave de ECH |
| TCP / UDP | Transmission Control Protocol / User Datagram Protocol | Protocolos de transporte sobre IP |
| TLS | Transport Layer Security | El protocolo de cifrado de este documento |
| TOTP | Time-based One-Time Password | Código de un solo uso basado en la hora (RFC 6238) |
| WebAuthn | Web Authentication | API del W3C para autenticar con claves públicas; base de las passkeys |
| X.509 | Estándar ITU-T X.509 | Formato de los certificados de clave pública |
| X25519 | Curva25519 para Diffie-Hellman | Grupo ECDHE más usado en TLS 1.3 |
| XSS | Cross-Site Scripting | Inyección de JavaScript en una página para robar datos o actuar como el usuario |

## Anexo B: cliente y servidor en C con OpenSSL

Un servidor de eco y un cliente que se conectan con SSL 3.0, TLS 1.2 o TLS 1.3, según el argumento que se les pase. Los dos fijan la versión mínima y máxima al mismo valor, así que solo aceptan ese protocolo. Están probados con OpenSSL 3.0.13 en Linux.

### Requisitos y certificados

Hacen falta `gcc` y las cabeceras de OpenSSL (`libssl-dev` en Debian/Ubuntu). El cliente verifica el certificado del servidor, así que primero se crea una CA de pruebas y un certificado para `localhost` firmado por ella:

```bash
sudo apt install build-essential libssl-dev

# CA de pruebas (keyUsage y basicConstraints: los exigen clientes estrictos como Python 3.13)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 365 -subj "/CN=Mi CA de pruebas" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Certificado del servidor para localhost, firmado por la CA
openssl req -newkey rsa:2048 -nodes -keyout servidor.key -out servidor.csr \
  -subj "/CN=localhost"
cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
openssl x509 -req -in servidor.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out servidor.pem -days 365 -extfile san.ext
```

### servidor.c

```c
/*
 * servidor.c - Servidor de eco sobre SSL 3.0, TLS 1.2 o TLS 1.3 con OpenSSL.
 *
 * Compilar:  gcc -Wall -o servidor servidor.c -lssl -lcrypto
 * Uso:       ./servidor <puerto> <ssl3|tls1.2|tls1.3> <cert.pem> <key.pem>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Traduce el nombre del protocolo a la constante de OpenSSL. */
static int version_protocolo(const char *nombre)
{
    if (strcmp(nombre, "ssl3") == 0)   return SSL3_VERSION;
    if (strcmp(nombre, "tls1.2") == 0) return TLS1_2_VERSION;
    if (strcmp(nombre, "tls1.3") == 0) return TLS1_3_VERSION;
    return -1;
}

static void fallo(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static SSL_CTX *crear_contexto(int version, const char *cert, const char *clave)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
        fallo("no se pudo crear el contexto SSL");

    /* Fijar mínimo y máximo a la misma versión: solo se acepta esa. */
    if (!SSL_CTX_set_min_proto_version(ctx, version) ||
        !SSL_CTX_set_max_proto_version(ctx, version))
        fallo("versión de protocolo no soportada por esta OpenSSL");

    if (version == SSL3_VERSION) {
        /* SSL 3.0 es inseguro: OpenSSL lo bloquea salvo con nivel de
         * seguridad 0 y una librería compilada con enable-ssl3. */
        SSL_CTX_set_security_level(ctx, 0);
        if (!SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"))
            fallo("no hay cifrados disponibles para SSL 3.0");
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0)
        fallo("no se pudo cargar el certificado");
    if (SSL_CTX_use_PrivateKey_file(ctx, clave, SSL_FILETYPE_PEM) <= 0)
        fallo("no se pudo cargar la clave privada");
    if (!SSL_CTX_check_private_key(ctx))
        fallo("la clave privada no corresponde al certificado");

    return ctx;
}

static int crear_socket(int puerto)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int uno = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &uno, sizeof(uno));

    struct sockaddr_in dir = {0};
    dir.sin_family = AF_INET;
    dir.sin_port = htons(puerto);
    dir.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&dir, sizeof(dir)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

static void atender(SSL_CTX *ctx, int cliente)
{
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, cliente);

    /* Handshake: aquí se negocian versión, cifrado y claves. */
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Handshake fallido\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }

    printf("Conexión: %s, cifrado %s\n", SSL_get_version(ssl),
           SSL_get_cipher_name(ssl));

    char buf[1024];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Recibido: %s\n", buf);

        char respuesta[1100];
        int len = snprintf(respuesta, sizeof(respuesta), "Eco (%s): %s",
                           SSL_get_version(ssl), buf);
        SSL_write(ssl, respuesta, len);
    }

    SSL_shutdown(ssl);   /* Envía la alerta close_notify. */
    SSL_free(ssl);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "Uso: %s <puerto> <ssl3|tls1.2|tls1.3> <cert.pem> <key.pem>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    int version = version_protocolo(argv[2]);
    if (version < 0) {
        fprintf(stderr, "Protocolo desconocido: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    setvbuf(stdout, NULL, _IONBF, 0);   /* Mostrar los mensajes al instante */

    SSL_CTX *ctx = crear_contexto(version, argv[3], argv[4]);
    int s = crear_socket(atoi(argv[1]));
    printf("Escuchando en el puerto %s con %s\n", argv[1], argv[2]);

    for (;;) {
        struct sockaddr_in dir;
        socklen_t len = sizeof(dir);
        int cliente = accept(s, (struct sockaddr *)&dir, &len);
        if (cliente < 0) {
            perror("accept");
            continue;
        }
        atender(ctx, cliente);
        close(cliente);
    }

    close(s);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
```

### cliente.c

```c
/*
 * cliente.c - Cliente para SSL 3.0, TLS 1.2 o TLS 1.3 con OpenSSL.
 *
 * Compilar:  gcc -Wall -o cliente cliente.c -lssl -lcrypto
 * Uso:       ./cliente <host> <puerto> <ssl3|tls1.2|tls1.3> <ca.pem> [mensaje]
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

static int version_protocolo(const char *nombre)
{
    if (strcmp(nombre, "ssl3") == 0)   return SSL3_VERSION;
    if (strcmp(nombre, "tls1.2") == 0) return TLS1_2_VERSION;
    if (strcmp(nombre, "tls1.3") == 0) return TLS1_3_VERSION;
    return -1;
}

static void fallo(const char *msg)
{
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static SSL_CTX *crear_contexto(int version, const char *ca)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        fallo("no se pudo crear el contexto SSL");

    if (!SSL_CTX_set_min_proto_version(ctx, version) ||
        !SSL_CTX_set_max_proto_version(ctx, version))
        fallo("versión de protocolo no soportada por esta OpenSSL");

    if (version == SSL3_VERSION) {
        SSL_CTX_set_security_level(ctx, 0);
        if (!SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"))
            fallo("no hay cifrados disponibles para SSL 3.0");
    }

    /* Verificar el certificado del servidor contra nuestra CA. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) <= 0)
        fallo("no se pudo cargar el certificado de la CA");

    return ctx;
}

static int conectar(const char *host, const char *puerto)
{
    struct addrinfo pistas = {0}, *res, *p;
    pistas.ai_family = AF_UNSPEC;
    pistas.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, puerto, &pistas, &res);
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
        fprintf(stderr, "No se pudo conectar a %s:%s\n", host, puerto);
        exit(EXIT_FAILURE);
    }
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6) {
        fprintf(stderr, "Uso: %s <host> <puerto> <ssl3|tls1.2|tls1.3> <ca.pem> [mensaje]\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    const char *host = argv[1];
    const char *mensaje = argc == 6 ? argv[5] : "Hola, servidor";

    int version = version_protocolo(argv[3]);
    if (version < 0) {
        fprintf(stderr, "Protocolo desconocido: %s\n", argv[3]);
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = crear_contexto(version, argv[4]);
    int s = conectar(host, argv[2]);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, s);
    SSL_set_tlsext_host_name(ssl, host);   /* SNI */
    SSL_set1_host(ssl, host);              /* El certificado debe ser de este host */

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Handshake fallido (verificación: %s)\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    printf("Conectado con %s, cifrado %s\n", SSL_get_version(ssl),
           SSL_get_cipher_name(ssl));

    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (cert) {
        char sujeto[256];
        X509_NAME_oneline(X509_get_subject_name(cert), sujeto, sizeof(sujeto));
        printf("Certificado del servidor: %s\n", sujeto);
        X509_free(cert);
    }

    SSL_write(ssl, mensaje, strlen(mensaje));

    char buf[1200];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Respuesta: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(s);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
```

### Compilar y probar TLS 1.2 y TLS 1.3

```bash
gcc -Wall -o servidor servidor.c -lssl -lcrypto
gcc -Wall -o cliente cliente.c -lssl -lcrypto

# Terminal 1
./servidor 4433 tls1.3 servidor.pem servidor.key

# Terminal 2
./cliente localhost 4433 tls1.3 ca.pem "Hola tls1.3"
```

Salida real de las pruebas:

```
Conectado con TLSv1.3, cifrado TLS_AES_256_GCM_SHA384
Certificado del servidor: /CN=localhost
Respuesta: Eco (TLSv1.3): Hola tls1.3

Conectado con TLSv1.2, cifrado ECDHE-RSA-AES256-GCM-SHA384
Certificado del servidor: /CN=localhost
Respuesta: Eco (TLSv1.2): Hola tls1.2
```

El nombre del cifrado ya muestra la diferencia entre versiones: en TLS 1.3 la suite solo indica AEAD y hash (`TLS_AES_256_GCM_SHA384`), mientras que en TLS 1.2 incluye también el intercambio y la autenticación (`ECDHE-RSA-...`).

Si cliente y servidor piden versiones distintas (servidor en `tls1.3`, cliente en `tls1.2`), el handshake falla con la alerta `protocol_version` (número 70):

```
Handshake fallido (verificación: ok)
...:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:...:SSL alert number 70
```

### SSL 3.0: requiere una OpenSSL compilada a propósito

Las OpenSSL de Debian, Ubuntu y la mayoría de distribuciones se compilan sin SSL 3.0. Con ellas, el modo `ssl3` falla en los dos lados con `no protocols available`. Para probarlo hay que compilar OpenSSL con `enable-ssl3` en un directorio aparte, sin tocar la del sistema:

```bash
git clone --depth 1 --branch openssl-3.0.13 https://github.com/openssl/openssl.git
cd openssl
./Configure enable-ssl3 enable-ssl3-method no-tests --prefix=$HOME/ossl-ssl3 --libdir=lib
make -j$(nproc) && make install_sw
cd ..

O=$HOME/ossl-ssl3
gcc -Wall -I$O/include -o servidor3 servidor.c -L$O/lib -Wl,-rpath,$O/lib -lssl -lcrypto
gcc -Wall -I$O/include -o cliente3 cliente.c -L$O/lib -Wl,-rpath,$O/lib -lssl -lcrypto

./servidor3 4433 ssl3 servidor.pem servidor.key     # terminal 1
./cliente3 localhost 4433 ssl3 ca.pem "Hola ssl3"   # terminal 2
```

Salida real con esa compilación:

```
Conectado con SSLv3, cifrado AES256-SHA
Certificado del servidor: /CN=localhost
Respuesta: Eco (SSLv3): Hola ssl3
```

El cifrado negociado, `AES256-SHA`, usa intercambio RSA estático, CBC y MAC con SHA-1: sin forward secrecy y vulnerable a POODLE. Por eso el código baja el nivel de seguridad a 0 solo en ese modo. Es útil para estudiar el protocolo en un laboratorio, nunca para un servicio real.

### Ver el handshake en Wireshark

Para descifrar el tráfico de estos programas en Wireshark, añade esta línea en `crear_contexto()` de cualquiera de los dos, justo después de `SSL_CTX_new`, y la función de callback al principio del fichero:

```c
static void log_claves(const SSL *ssl, const char *linea)
{
    (void)ssl;
    FILE *f = fopen("/tmp/keys.log", "a");
    if (f) {
        fprintf(f, "%s\n", linea);
        fclose(f);
    }
}

/* En crear_contexto(): */
SSL_CTX_set_keylog_callback(ctx, log_claves);
```

Captura con `sudo tcpdump -i lo -w tls.pcap port 4433`, abre el fichero en Wireshark y carga `/tmp/keys.log` en Preferencias → Protocols → TLS → (Pre)-Master-Secret log filename. Verás cada mensaje de los diagramas de este documento, incluidos los cifrados de TLS 1.3.

### Script para probarlo todo: probar\_tls.sh

El script hace todo el proceso de una vez: comprueba las dependencias, crea los certificados, compila, lanza servidor y cliente en cada modo y comprueba que el resultado es el esperado. Guárdalo junto a `servidor.c` y `cliente.c`:

```bash
chmod +x probar_tls.sh
./probar_tls.sh            # TLS 1.3, TLS 1.2, versiones incompatibles y SSL 3.0 con la OpenSSL del sistema
./probar_tls.sh --ssl3     # Además compila una OpenSSL con SSL 3.0 y prueba ese protocolo
./probar_tls.sh --limpiar  # Borra certificados, binarios y logs
PUERTO=8443 ./probar_tls.sh  # Usar otro puerto
```

Con `--ssl3` necesita además `git`, `make` y `perl` para compilar OpenSSL. La primera vez tarda unos minutos; después reutiliza la compilación de `$HOME/ossl-ssl3`.

| Prueba | Servidor | Cliente | Resultado esperado |
| --- | --- | --- | --- |
| tls1.3 | TLS 1.3 | TLS 1.3 | Conecta y devuelve el eco |
| tls1.2 | TLS 1.2 | TLS 1.2 | Conecta y devuelve el eco |
| incompatible | TLS 1.3 | TLS 1.2 | Falla con la alerta protocol\_version |
| ssl3-sistema | SSL 3.0 | SSL 3.0 | Solo informa si la OpenSSL del sistema soporta SSL 3.0 |
| ssl3 (con --ssl3) | SSL 3.0 | SSL 3.0 | Conecta con la OpenSSL compilada aparte |

```bash
#!/usr/bin/env bash
#
# probar_tls.sh - Crea los certificados, compila servidor.c y cliente.c y
# prueba la conexión con TLS 1.3, TLS 1.2 y, opcionalmente, SSL 3.0.
#
# Uso:
#   ./probar_tls.sh           Prueba TLS 1.3, TLS 1.2 y versiones incompatibles
#   ./probar_tls.sh --ssl3    Además compila una OpenSSL con SSL 3.0 y lo prueba
#   ./probar_tls.sh --limpiar Borra certificados, binarios y logs generados
#
# Variables opcionales:
#   PUERTO=4433                    Puerto del servidor
#   OSSL_SSL3=$HOME/ossl-ssl3      Dónde instalar/buscar la OpenSSL con SSL 3.0
#   OSSL_VERSION=openssl-3.0.13    Etiqueta de OpenSSL que se compila para SSL 3.0

set -euo pipefail

PUERTO="${PUERTO:-4433}"
OSSL_SSL3="${OSSL_SSL3:-$HOME/ossl-ssl3}"
OSSL_VERSION="${OSSL_VERSION:-openssl-3.0.13}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"

cd "$DIR"

# --- Utilidades -------------------------------------------------------------

VERDE=$'\e[32m'; ROJO=$'\e[31m'; AZUL=$'\e[34m'; NORMAL=$'\e[0m'
[ -t 1 ] || { VERDE=""; ROJO=""; AZUL=""; NORMAL=""; }

titulo() { echo; echo "${AZUL}== $*${NORMAL}"; }
ok()     { echo "${VERDE}[OK]${NORMAL} $*"; }
error()  { echo "${ROJO}[FALLO]${NORMAL} $*"; }

PID_SERVIDOR=""
parar_servidor() {
    if [ -n "$PID_SERVIDOR" ] && kill -0 "$PID_SERVIDOR" 2>/dev/null; then
        kill "$PID_SERVIDOR" 2>/dev/null || true
        wait "$PID_SERVIDOR" 2>/dev/null || true
    fi
    PID_SERVIDOR=""
}
trap parar_servidor EXIT INT TERM

limpiar() {
    rm -f ca.key ca.pem ca.srl servidor.key servidor.csr servidor.pem san.ext \
          servidor cliente servidor3 cliente3
    rm -rf "$LOGS"
    echo "Ficheros generados borrados."
}

# --- 1. Dependencias --------------------------------------------------------

comprobar_dependencias() {
    titulo "Comprobando dependencias"
    local falta=0
    for cmd in gcc openssl; do
        if command -v "$cmd" >/dev/null; then
            ok "$cmd encontrado"
        else
            error "falta $cmd"; falta=1
        fi
    done
    if echo '#include <openssl/ssl.h>' | gcc -E - >/dev/null 2>&1; then
        ok "cabeceras de OpenSSL encontradas"
    else
        error "faltan las cabeceras de OpenSSL (sudo apt install libssl-dev)"; falta=1
    fi
    for f in servidor.c cliente.c; do
        [ -f "$f" ] || { error "no encuentro $f en $DIR"; falta=1; }
    done
    [ "$falta" -eq 0 ] || exit 1
    echo "OpenSSL del sistema: $(openssl version)"
}

# --- 2. Certificados --------------------------------------------------------

crear_certificados() {
    titulo "Certificados"
    if [ -f ca.pem ] && [ -f servidor.pem ] && [ -f servidor.key ]; then
        ok "ya existen, se reutilizan (usa --limpiar para regenerarlos)"
        return
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
        -days 365 -subj "/CN=Mi CA de pruebas" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    ok "CA de pruebas creada (ca.pem)"

    openssl req -newkey rsa:2048 -nodes -keyout servidor.key -out servidor.csr \
        -subj "/CN=localhost" 2>/dev/null
    cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
    openssl x509 -req -in servidor.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out servidor.pem -days 365 -extfile san.ext 2>/dev/null
    ok "certificado del servidor para localhost (servidor.pem)"

    openssl verify -CAfile ca.pem servidor.pem >/dev/null && ok "la cadena verifica"
}

# --- 3. Compilación ---------------------------------------------------------

compilar() {
    titulo "Compilando con la OpenSSL del sistema"
    gcc -Wall -Wextra -o servidor servidor.c -lssl -lcrypto
    gcc -Wall -Wextra -o cliente cliente.c -lssl -lcrypto
    ok "servidor y cliente compilados"
}

compilar_openssl_ssl3() {
    titulo "OpenSSL con SSL 3.0 en $OSSL_SSL3"
    if [ -f "$OSSL_SSL3/lib/libssl.so" ]; then
        ok "ya estaba compilada, se reutiliza"
    else
        local src
        src="$(mktemp -d)"
        echo "Descargando $OSSL_VERSION y compilando (tarda unos minutos)..."
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
        ok "OpenSSL instalada en $OSSL_SSL3"
    fi

    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o servidor3 servidor.c \
        -L"$OSSL_SSL3/lib" -Wl,-rpath,"$OSSL_SSL3/lib" -lssl -lcrypto
    gcc -Wall -Wextra -I"$OSSL_SSL3/include" -o cliente3 cliente.c \
        -L"$OSSL_SSL3/lib" -Wl,-rpath,"$OSSL_SSL3/lib" -lssl -lcrypto
    ok "servidor3 y cliente3 compilados contra esa OpenSSL"
}

# --- 4. Pruebas -------------------------------------------------------------

FALLOS=0

# probar <nombre> <bin_servidor> <proto_servidor> <bin_cliente> <proto_cliente> <si|no|info>
#   si: debe conectar · no: el handshake debe fallar · info: solo informa
probar() {
    local nombre="$1" srv="$2" psrv="$3" cli="$4" pcli="$5" esperado="$6"
    local log_srv="$LOGS/$nombre.servidor.log" log_cli="$LOGS/$nombre.cliente.log"

    titulo "Prueba: $nombre (servidor $psrv, cliente $pcli)"

    "./$srv" "$PUERTO" "$psrv" servidor.pem servidor.key >"$log_srv" 2>&1 &
    PID_SERVIDOR=$!

    # Esperar a que el servidor esté escuchando (máximo 5 s).
    local i
    for i in $(seq 50); do
        grep -q "Escuchando" "$log_srv" 2>/dev/null && break
        if ! kill -0 "$PID_SERVIDOR" 2>/dev/null; then break; fi
        sleep 0.1
    done
    if ! grep -q "Escuchando" "$log_srv"; then
        error "el servidor no arrancó"; sed 's/^/    /' "$log_srv"
        FALLOS=$((FALLOS + 1)); parar_servidor; return
    fi

    local rc=0
    timeout 10 "./$cli" localhost "$PUERTO" "$pcli" ca.pem "Hola desde $pcli" \
        >"$log_cli" 2>&1 || rc=$?
    sleep 0.2
    parar_servidor

    echo "  Cliente:"; sed 's/^/    /' "$log_cli"
    echo "  Servidor:"; sed 's/^/    /' "$log_srv"

    if [ "$esperado" = "si" ] && [ "$rc" -eq 0 ] && grep -q "^Respuesta:" "$log_cli"; then
        ok "conexión y eco correctos"
    elif [ "$esperado" = "no" ] && [ "$rc" -ne 0 ]; then
        ok "el handshake falla, como se esperaba"
    elif [ "$esperado" = "info" ]; then
        if [ "$rc" -eq 0 ]; then
            ok "esta OpenSSL sí soporta $pcli"
        else
            ok "esta OpenSSL no soporta $pcli (lo normal en las distribuciones)"
        fi
    else
        error "resultado inesperado (código de salida del cliente: $rc)"
        FALLOS=$((FALLOS + 1))
    fi
}

# --- Programa principal -----------------------------------------------------

CON_SSL3=0
case "${1:-}" in
    --limpiar) limpiar; exit 0 ;;
    --ssl3)    CON_SSL3=1 ;;
    "")        ;;
    *)         echo "Uso: $0 [--ssl3 | --limpiar]"; exit 1 ;;
esac

comprobar_dependencias
crear_certificados
compilar
mkdir -p "$LOGS"

probar tls1.3       servidor tls1.3 cliente tls1.3 si
probar tls1.2       servidor tls1.2 cliente tls1.2 si
probar incompatible servidor tls1.3 cliente tls1.2 no
probar ssl3-sistema servidor ssl3   cliente ssl3   info

if [ "$CON_SSL3" -eq 1 ]; then
    command -v git >/dev/null || { error "--ssl3 necesita git"; exit 1; }
    compilar_openssl_ssl3
    probar ssl3 servidor3 ssl3 cliente3 ssl3 si
fi

titulo "Resumen"
if [ "$FALLOS" -eq 0 ]; then
    ok "todas las pruebas se comportaron como se esperaba (logs en $LOGS)"
else
    error "$FALLOS prueba(s) con resultado inesperado (logs en $LOGS)"
    exit 1
fi
```

Resumen de una ejecución real con `--ssl3`, compilando OpenSSL desde cero (el script también muestra la salida completa de cliente y servidor en cada prueba):

```
== Prueba: tls1.3 (servidor tls1.3, cliente tls1.3)
[OK] conexión y eco correctos
== Prueba: tls1.2 (servidor tls1.2, cliente tls1.2)
[OK] conexión y eco correctos
== Prueba: incompatible (servidor tls1.3, cliente tls1.2)
[OK] el handshake falla, como se esperaba
== Prueba: ssl3-sistema (servidor ssl3, cliente ssl3)
[OK] esta OpenSSL no soporta ssl3 (lo normal en las distribuciones)
== OpenSSL con SSL 3.0 en /home/juan/ossl-ssl3
[OK] OpenSSL instalada en /home/juan/ossl-ssl3
[OK] servidor3 y cliente3 compilados contra esa OpenSSL
== Prueba: ssl3 (servidor ssl3, cliente ssl3)
[OK] conexión y eco correctos
== Resumen
[OK] todas las pruebas se comportaron como se esperaba (logs en ./logs)
```

## Anexo C: ejemplos de código de autenticación

Un servidor HTTPS en Python con Flask que implementa lo explicado en "Autenticación web en detalle", y un cliente que comprueba cada mecanismo, incluidos los ataques que deben fallar. Un script lo prepara y lo ejecuta todo. Está probado con Python 3.13: las 27 comprobaciones pasan.

| Fichero | Contenido |
| --- | --- |
| `auth_utils.py` | Hash Argon2id, TOTP implementado a mano según el RFC 6238, PKCE, access tokens JWT ES256 y refresh tokens rotatorios con detección de reutilización |
| `servidor_auth.py` | Login con contraseña y TOTP, sesión en servidor con cookie `__Host-`, defensa CSRF por `Origin`, bloqueo tras 5 fallos, API protegida con Bearer |
| `cliente_auth.py` | 27 comprobaciones: vectores de los RFC, flujo de login, CSRF, `alg=none`, token manipulado, reutilización de refresh token y logout |
| `probar_auth.sh` | Crea un entorno virtual, instala dependencias, genera certificados, arranca el servidor y lanza el cliente |

Es código para aprender: guarda los datos en memoria y usa el servidor de desarrollo de Flask. En producción, las sesiones y los refresh tokens irían en Redis o en una base de datos, las claves de firma en un almacén de secretos, el servidor detrás de Gunicorn y un proxy inverso, y el login de usuarios probablemente en un proveedor OIDC (Keycloak, Entra ID, Auth0).

Para probarlo, pon los cuatro ficheros en una carpeta y ejecuta:

```bash
chmod +x probar_auth.sh
./probar_auth.sh            # Instala dependencias y ejecuta todas las pruebas
./probar_auth.sh --limpiar  # Borra el entorno virtual, certificados y logs
```

Solo necesita `python3` con el módulo `venv` (`sudo apt install python3-venv` en Debian/Ubuntu), `openssl` y `curl`.

### auth\_utils.py

```python
"""
auth_utils.py - Piezas de autenticación reutilizables:
contraseñas con Argon2id, TOTP (RFC 6238), PKCE (RFC 7636) y
tokens de acceso JWT con refresh tokens rotatorios.
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
# Contraseñas: Argon2id con sal aleatoria (la librería la genera y la guarda
# dentro de la propia cadena del hash).
# --------------------------------------------------------------------------

_ph = PasswordHasher()                       # Argon2id, parámetros de RFC 9106
_HASH_FICTICIO = _ph.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verificar_password(hash_guardado, password: str):
    """Devuelve (correcta, hash_nuevo).

    hash_nuevo no es None cuando los parámetros guardados están desfasados
    y conviene actualizar el hash en la base de datos.
    """
    if hash_guardado is None:
        # El usuario no existe: se calcula igualmente un hash para que el
        # tiempo de respuesta no revele qué usuarios existen.
        try:
            _ph.verify(_HASH_FICTICIO, password)
        except VerifyMismatchError:
            pass
        return False, None

    try:
        _ph.verify(hash_guardado, password)   # Compara en tiempo constante
    except (VerifyMismatchError, InvalidHashError):
        return False, None

    nuevo = _ph.hash(password) if _ph.check_needs_rehash(hash_guardado) else None
    return True, nuevo


# --------------------------------------------------------------------------
# TOTP (RFC 6238): el mismo cálculo que hacen las apps de autenticación.
# --------------------------------------------------------------------------

def nuevo_secreto_totp() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()   # 160 bits


def totp(secreto_b32: str, instante=None, paso=30, digitos=6) -> str:
    clave = base64.b32decode(secreto_b32.upper() + "=" * (-len(secreto_b32) % 8))
    contador = int((time.time() if instante is None else instante) // paso)
    mac = hmac.new(clave, struct.pack(">Q", contador), hashlib.sha1).digest()
    desplazamiento = mac[-1] & 0x0F                     # Truncado dinámico
    numero = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0]
    return str((numero & 0x7FFFFFFF) % 10 ** digitos).zfill(digitos)


def verificar_totp(secreto_b32: str, codigo: str, ultimo_paso_usado=None,
                   ventana=1, paso=30):
    """Devuelve el número de paso aceptado, o None.

    Acepta el intervalo actual y `ventana` intervalos antes y después
    (desfase de reloj), y rechaza códigos de pasos ya usados.
    """
    ahora = int(time.time() // paso)
    for p in range(ahora - ventana, ahora + ventana + 1):
        if ultimo_paso_usado is not None and p <= ultimo_paso_usado:
            continue
        if hmac.compare_digest(totp(secreto_b32, p * paso, paso), codigo):
            return p
    return None


def uri_totp(secreto_b32: str, usuario: str, emisor: str) -> str:
    """URI que se muestra como código QR al dar de alta el segundo factor."""
    return f"otpauth://totp/{emisor}:{usuario}?secret={secreto_b32}&issuer={emisor}"


# --------------------------------------------------------------------------
# PKCE (RFC 7636)
# --------------------------------------------------------------------------

def b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def challenge_s256(code_verifier: str) -> str:
    return b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def generar_pkce():
    """Devuelve (code_verifier, code_challenge)."""
    code_verifier = b64url(secrets.token_bytes(32))     # 43 caracteres
    return code_verifier, challenge_s256(code_verifier)


# --------------------------------------------------------------------------
# Tokens: access token JWT (ES256, vida corta) + refresh token opaco rotatorio
# --------------------------------------------------------------------------

class ErrorToken(Exception):
    pass


def _sha256(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


class EmisorTokens:
    def __init__(self, emisor, audiencia, vida_access=900, vida_refresh=7 * 86400):
        self.emisor = emisor
        self.audiencia = audiencia
        self.vida_access = vida_access
        self.vida_refresh = vida_refresh
        # Par de claves de curva elíptica: se firma con la privada y
        # cualquier servicio puede verificar con la pública.
        self.clave_privada = ec.generate_private_key(ec.SECP256R1())
        self.clave_publica = self.clave_privada.public_key()
        self.kid = secrets.token_hex(4)
        # Refresh tokens guardados por su hash, nunca en claro.
        self._refresh = {}
        self._familias_revocadas = set()

    # --- Access token -----------------------------------------------------

    def emitir_access(self, sub: str, scope: str) -> str:
        ahora = int(time.time())
        claims = {
            "iss": self.emisor,
            "sub": sub,
            "aud": self.audiencia,
            "iat": ahora,
            "exp": ahora + self.vida_access,
            "jti": secrets.token_hex(8),
            "scope": scope,
        }
        return jwt.encode(claims, self.clave_privada, algorithm="ES256",
                          headers={"kid": self.kid})

    def validar_access(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self.clave_publica,
                algorithms=["ES256"],          # Fijado: nunca el que diga el token
                audience=self.audiencia,
                issuer=self.emisor,
                leeway=30,                     # Margen por desfase de relojes
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as e:
            raise ErrorToken(f"access token no válido: {e}") from e

    # --- Refresh token ----------------------------------------------------

    def emitir_refresh(self, sub: str, scope: str, familia=None) -> str:
        token = "rt_" + secrets.token_urlsafe(32)
        self._refresh[_sha256(token)] = {
            "sub": sub,
            "scope": scope,
            "familia": familia or secrets.token_hex(8),
            "usado": False,
            "exp": time.time() + self.vida_refresh,
        }
        return token

    def renovar(self, refresh_token: str):
        """Canjea un refresh token por (access, refresh) nuevos y lo invalida."""
        datos = self._refresh.get(_sha256(refresh_token))
        if (datos is None or datos["exp"] < time.time()
                or datos["familia"] in self._familias_revocadas):
            raise ErrorToken("refresh token no válido")
        if datos["usado"]:
            # Reutilización: alguien tiene una copia. Se revoca toda la familia.
            self._familias_revocadas.add(datos["familia"])
            raise ErrorToken("refresh token reutilizado: sesión revocada")
        datos["usado"] = True
        return (self.emitir_access(datos["sub"], datos["scope"]),
                self.emitir_refresh(datos["sub"], datos["scope"], datos["familia"]))

    def revocar(self, refresh_token: str):
        datos = self._refresh.get(_sha256(refresh_token))
        if datos:
            self._familias_revocadas.add(datos["familia"])
```

### servidor\_auth.py

```python
"""
servidor_auth.py - Servidor de ejemplo con:
  * login con contraseña (Argon2id) + segundo factor TOTP
  * sesión en servidor con cookie __Host-, regenerada al autenticar
  * defensa CSRF comprobando la cabecera Origin
  * emisión de access token JWT + refresh token rotatorio para una API

Uso: python3 servidor_auth.py   (HTTPS en https://localhost:5443)
Solo para aprender: datos en memoria y un usuario de prueba.
"""
import os
import secrets
import time
from functools import wraps

from flask import Flask, g, jsonify, request

from auth_utils import (EmisorTokens, ErrorToken, hash_password,
                        verificar_password, verificar_totp)

PUERTO = int(os.environ.get("PUERTO_AUTH", "5443"))
ORIGEN = f"https://localhost:{PUERTO}"
COOKIE = "__Host-session"
INACTIVIDAD = 30 * 60          # Cierre por inactividad: 30 minutos
DURACION_MAXIMA = 12 * 3600    # Cierre absoluto: 12 horas
MAX_FALLOS, BLOQUEO = 5, 60    # 5 intentos fallidos -> 60 s bloqueado

app = Flask(__name__)

# "Base de datos" en memoria. La contraseña solo existe como hash.
USUARIOS = {
    "juan": {
        "hash": hash_password("caballo-correcto-bateria-grapa"),
        "totp": os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP"),
        "ultimo_paso_totp": None,
        "scope": "pedidos:leer",
        "fallos": 0,
        "bloqueado_hasta": 0,
    }
}
SESIONES = {}   # id de sesión -> datos
tokens = EmisorTokens(emisor=ORIGEN, audiencia=ORIGEN + "/api")


# --------------------------------------------------------------------------
# Sesiones
# --------------------------------------------------------------------------

def crear_sesion(usuario, mfa_ok):
    sid = secrets.token_urlsafe(32)          # 256 bits aleatorios
    ahora = time.time()
    SESIONES[sid] = {"usuario": usuario, "mfa_ok": mfa_ok,
                     "creada": ahora, "actividad": ahora}
    return sid


def poner_cookie(respuesta, sid):
    respuesta.set_cookie(COOKIE, sid, path="/", secure=True, httponly=True,
                         samesite="Lax", max_age=DURACION_MAXIMA)
    return respuesta


def sesion_actual():
    sid = request.cookies.get(COOKIE)
    datos = SESIONES.get(sid) if sid else None
    if not datos:
        return None, None
    ahora = time.time()
    if (ahora - datos["actividad"] > INACTIVIDAD
            or ahora - datos["creada"] > DURACION_MAXIMA):
        SESIONES.pop(sid, None)
        return None, None
    datos["actividad"] = ahora
    return sid, datos


def requiere_sesion(f):
    @wraps(f)
    def envoltorio(*args, **kwargs):
        sid, datos = sesion_actual()
        if not datos or not datos["mfa_ok"]:
            return jsonify(error="no autenticado"), 401
        g.sid, g.usuario = sid, datos["usuario"]
        return f(*args, **kwargs)
    return envoltorio


def requiere_token(scope):
    def decorador(f):
        @wraps(f)
        def envoltorio(*args, **kwargs):
            cabecera = request.headers.get("Authorization", "")
            if not cabecera.startswith("Bearer "):
                return jsonify(error="falta el token"), 401, \
                    {"WWW-Authenticate": 'Bearer realm="api"'}
            try:
                claims = tokens.validar_access(cabecera[7:])
            except ErrorToken as e:
                return jsonify(error=str(e)), 401, \
                    {"WWW-Authenticate": 'Bearer error="invalid_token"'}
            if scope not in claims.get("scope", "").split():
                return jsonify(error="permiso insuficiente"), 403
            g.claims = claims
            return f(*args, **kwargs)
        return envoltorio
    return decorador


@app.before_request
def defensa_csrf():
    # Los navegadores envían Origin en las peticiones que cambian estado.
    # Si viene de otro sitio, se rechaza. (SameSite=Lax es la primera barrera.)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origen = request.headers.get("Origin")
        if origen is not None and origen != ORIGEN:
            return jsonify(error="origen no permitido"), 403


# --------------------------------------------------------------------------
# Login con contraseña + TOTP
# --------------------------------------------------------------------------

@app.post("/login")
def login():
    datos = request.get_json(silent=True) or {}
    nombre, password = datos.get("usuario", ""), datos.get("password", "")
    usuario = USUARIOS.get(nombre)

    if usuario and usuario["bloqueado_hasta"] > time.time():
        return jsonify(error="demasiados intentos, espera"), 429

    ok, hash_nuevo = verificar_password(usuario["hash"] if usuario else None, password)
    if not ok:
        if usuario:
            usuario["fallos"] += 1
            if usuario["fallos"] >= MAX_FALLOS:
                usuario["bloqueado_hasta"] = time.time() + BLOQUEO
                usuario["fallos"] = 0
        # Mismo mensaje exista o no el usuario
        return jsonify(error="usuario o contraseña incorrectos"), 401

    usuario["fallos"] = 0
    if hash_nuevo:
        usuario["hash"] = hash_nuevo

    # Contra la fijación de sesión: se descarta cualquier sesión previa
    # y se crea un identificador nuevo.
    sid_viejo = request.cookies.get(COOKIE)
    SESIONES.pop(sid_viejo, None)
    sid = crear_sesion(nombre, mfa_ok=False)
    return poner_cookie(jsonify(mfa_requerido=True), sid)


@app.post("/login/mfa")
def login_mfa():
    sid, datos = sesion_actual()
    if not datos:
        return jsonify(error="inicia sesión primero"), 401
    usuario = USUARIOS[datos["usuario"]]
    codigo = (request.get_json(silent=True) or {}).get("codigo", "")

    paso = verificar_totp(usuario["totp"], codigo, usuario["ultimo_paso_totp"])
    if paso is None:
        return jsonify(error="código incorrecto"), 401
    usuario["ultimo_paso_totp"] = paso         # Un código no se puede reutilizar

    # Cambio de privilegios: nuevo identificador de sesión otra vez.
    SESIONES.pop(sid, None)
    nuevo_sid = crear_sesion(datos["usuario"], mfa_ok=True)
    return poner_cookie(jsonify(ok=True), nuevo_sid)


@app.get("/perfil")
@requiere_sesion
def perfil():
    return jsonify(usuario=g.usuario)


@app.post("/logout")
def logout():
    sid = request.cookies.get(COOKIE)
    SESIONES.pop(sid, None)                    # Se borra en el servidor
    respuesta = jsonify(ok=True)
    respuesta.delete_cookie(COOKIE, path="/", secure=True, httponly=True,
                            samesite="Lax")
    return respuesta


# --------------------------------------------------------------------------
# API con tokens
# --------------------------------------------------------------------------

@app.post("/api/token")
@requiere_sesion
def emitir_tokens():
    """Entrega tokens a un usuario ya autenticado (por ejemplo, para una CLI)."""
    scope = USUARIOS[g.usuario]["scope"]
    return jsonify(access_token=tokens.emitir_access(g.usuario, scope),
                   refresh_token=tokens.emitir_refresh(g.usuario, scope),
                   token_type="Bearer", expires_in=tokens.vida_access)


@app.post("/api/refresh")
def renovar_tokens():
    refresh = (request.get_json(silent=True) or {}).get("refresh_token", "")
    try:
        access, nuevo_refresh = tokens.renovar(refresh)
    except ErrorToken as e:
        return jsonify(error=str(e)), 401
    return jsonify(access_token=access, refresh_token=nuevo_refresh,
                   token_type="Bearer", expires_in=tokens.vida_access)


@app.get("/api/pedidos")
@requiere_token("pedidos:leer")
def pedidos():
    return jsonify(usuario=g.claims["sub"], pedidos=[{"id": 1, "total": 42.5}])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PUERTO,
            ssl_context=("servidor.pem", "servidor.key"))
```

### cliente\_auth.py

```python
"""
cliente_auth.py - Prueba todos los mecanismos del servidor de ejemplo
y comprueba también las funciones de auth_utils con los vectores de los RFC.

Uso: python3 cliente_auth.py   (con servidor_auth.py en marcha)
"""
import base64
import json
import os
import sys

import requests

from auth_utils import (challenge_s256, generar_pkce, hash_password, totp,
                        verificar_password)

PUERTO = int(os.environ.get("PUERTO_AUTH", "5443"))
BASE = f"https://localhost:{PUERTO}"
TOTP_SECRET = os.environ.get("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
CA = "ca.pem"                       # Se verifica el certificado del servidor
fallos = 0


def comprobar(descripcion, condicion, detalle=""):
    global fallos
    estado = "OK    " if condicion else "FALLO "
    if not condicion:
        fallos += 1
    print(f"[{estado}] {descripcion}" + (f"  ({detalle})" if detalle else ""))


def decodificar_jwt(token):
    """Solo para mostrar el contenido: NO verifica la firma."""
    def parte(p):
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    cabecera, carga, _ = token.split(".")
    return parte(cabecera), parte(carga)


# --- 1. Funciones locales contra los vectores de prueba de los RFC ----------

print("== Funciones de auth_utils")
h = hash_password("secreto")
comprobar("hash Argon2id con sal", h.startswith("$argon2id$"), h[:30] + "...")
comprobar("dos hashes de la misma contraseña son distintos", h != hash_password("secreto"))
comprobar("verifica la contraseña correcta", verificar_password(h, "secreto")[0])
comprobar("rechaza la incorrecta", not verificar_password(h, "otra")[0])

# RFC 6238, apéndice B: secreto "12345678901234567890", T=59 s -> 94287082
secreto_rfc = base64.b32encode(b"12345678901234567890").decode()
comprobar("TOTP coincide con el vector del RFC 6238",
          totp(secreto_rfc, instante=59, digitos=8) == "94287082")

# RFC 7636, apéndice B
comprobar("PKCE S256 coincide con el vector del RFC 7636",
          challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
          == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
verifier, challenge = generar_pkce()
comprobar("PKCE genera un code_verifier de 43 caracteres", len(verifier) == 43,
          f"challenge={challenge[:12]}...")

# --- 2. Sesión con cookie + TOTP ---------------------------------------------

print("\n== Sesión con cookie y segundo factor")
s = requests.Session()
s.verify = CA
s.trust_env = False                 # Ignorar proxies y REQUESTS_CA_BUNDLE del entorno
s.headers["Origin"] = BASE          # Como haría un navegador en nuestro sitio

r = s.post(f"{BASE}/login", json={"usuario": "juan", "password": "mala"})
comprobar("contraseña incorrecta -> 401", r.status_code == 401)
r = s.post(f"{BASE}/login", json={"usuario": "nadie", "password": "x"})
comprobar("usuario inexistente -> mismo 401 y mismo mensaje",
          r.status_code == 401 and r.json()["error"] == "usuario o contraseña incorrectos")

r = s.post(f"{BASE}/login", json={"usuario": "juan",
                                  "password": "caballo-correcto-bateria-grapa"})
cookie_1 = s.cookies.get("__Host-session")
comprobar("contraseña correcta -> pide segundo factor", r.json().get("mfa_requerido") is True)
set_cookie = r.headers.get("Set-Cookie", "")
comprobar("cookie con Secure, HttpOnly y SameSite=Lax",
          all(a in set_cookie for a in ("Secure", "HttpOnly", "SameSite=Lax")),
          set_cookie.split(";")[0][:30] + "...")

r = s.get(f"{BASE}/perfil")
comprobar("sin segundo factor no hay acceso a /perfil", r.status_code == 401)

r = s.post(f"{BASE}/login/mfa", json={"codigo": "000000"})
comprobar("código TOTP incorrecto -> 401", r.status_code == 401)
codigo = totp(TOTP_SECRET)
r = s.post(f"{BASE}/login/mfa", json={"codigo": codigo})
cookie_2 = s.cookies.get("__Host-session")
comprobar("código TOTP correcto -> sesión completa", r.status_code == 200, f"código {codigo}")
comprobar("el ID de sesión cambia al autenticar (anti-fijación)", cookie_1 != cookie_2)

r = s.get(f"{BASE}/perfil")
comprobar("/perfil con sesión", r.status_code == 200, r.text.strip())

r = s.post(f"{BASE}/logout", headers={"Origin": "https://atacante.example"})
comprobar("CSRF: POST desde otro origen -> 403", r.status_code == 403)

# --- 3. Tokens para la API -----------------------------------------------------

print("\n== Access token JWT y refresh token")
r = s.post(f"{BASE}/api/token")
t = r.json()
access, refresh = t["access_token"], t["refresh_token"]
cabecera, carga = decodificar_jwt(access)
comprobar("se emiten access y refresh token", r.status_code == 200,
          f"alg={cabecera['alg']}, exp-iat={carga['exp'] - carga['iat']} s, scope={carga['scope']}")

api = requests.Session()
api.verify = CA
api.trust_env = False
r = api.get(f"{BASE}/api/pedidos")
comprobar("API sin token -> 401", r.status_code == 401)
r = api.get(f"{BASE}/api/pedidos", headers={"Authorization": f"Bearer {access}"})
comprobar("API con token -> 200", r.status_code == 200, r.text.strip())

# Ataque alg=none: misma carga, sin firma
falso = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
         + "." + access.split(".")[1] + ".")
r = api.get(f"{BASE}/api/pedidos", headers={"Authorization": f"Bearer {falso}"})
comprobar("token con alg=none -> rechazado", r.status_code == 401, r.json()["error"][:45])

# Carga modificada: la firma ya no cuadra
cab, car, firma = access.split(".")
carga_mod = dict(carga, sub="admin")
car_mod = base64.urlsafe_b64encode(json.dumps(carga_mod).encode()).rstrip(b"=").decode()
r = api.get(f"{BASE}/api/pedidos",
            headers={"Authorization": f"Bearer {cab}.{car_mod}.{firma}"})
comprobar("token con sub cambiado -> rechazado", r.status_code == 401)

r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
nuevo_refresh = r.json().get("refresh_token")
comprobar("refresh -> par de tokens nuevo", r.status_code == 200 and nuevo_refresh != refresh)
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": refresh})
comprobar("reutilizar el refresh antiguo -> 401", r.status_code == 401, r.json()["error"])
r = api.post(f"{BASE}/api/refresh", json={"refresh_token": nuevo_refresh})
comprobar("tras la reutilización, toda la familia queda revocada", r.status_code == 401)

# --- 4. Logout --------------------------------------------------------------------

print("\n== Cierre de sesión")
r = s.post(f"{BASE}/logout")
comprobar("logout -> 200", r.status_code == 200)
nuevo = requests.Session()
nuevo.verify, nuevo.trust_env = CA, False
r = nuevo.get(f"{BASE}/perfil", cookies={"__Host-session": cookie_2})
comprobar("la cookie antigua ya no sirve (sesión borrada en el servidor)", r.status_code == 401)

print(f"\n{'Todo correcto' if fallos == 0 else f'{fallos} comprobaciones fallidas'}")
sys.exit(1 if fallos else 0)
```

### probar\_auth.sh

```bash
#!/usr/bin/env bash
#
# probar_auth.sh - Prepara un entorno virtual de Python, crea los
# certificados (si no existen), arranca servidor_auth.py y lanza
# cliente_auth.py, que comprueba todos los mecanismos de autenticación.
#
# Uso: ./probar_auth.sh            Ejecuta las pruebas
#      ./probar_auth.sh --limpiar  Borra el entorno virtual, certificados y logs
#
# Variables opcionales: PUERTO_AUTH=5443

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
export PUERTO_AUTH="${PUERTO_AUTH:-5443}"

if [ "${1:-}" = "--limpiar" ]; then
    rm -rf .venv ca.key ca.pem ca.srl servidor.key servidor.csr servidor.pem \
           san.ext servidor_auth.log __pycache__
    echo "Ficheros generados borrados."
    exit 0
fi

PID=""
parar() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true; }
trap parar EXIT INT TERM

echo "== Entorno de Python"
command -v python3 >/dev/null || { echo "Falta python3"; exit 1; }
if [ ! -d .venv ]; then
    python3 -m venv .venv || { echo "Instala python3-venv (sudo apt install python3-venv)"; exit 1; }
fi
.venv/bin/pip install -q --disable-pip-version-check \
    flask argon2-cffi pyjwt cryptography requests
echo "Dependencias instaladas en .venv"

echo "== Certificados"
if [ ! -f servidor.pem ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
        -days 365 -subj "/CN=Mi CA de pruebas" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout servidor.key -out servidor.csr \
        -subj "/CN=localhost" 2>/dev/null
    cat > san.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid
EXT
    openssl x509 -req -in servidor.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out servidor.pem -days 365 -extfile san.ext 2>/dev/null
    echo "CA y certificado de localhost creados"
else
    echo "Se reutilizan los existentes"
fi

# Secreto TOTP compartido entre servidor y cliente solo para la demo.
TOTP_SECRET="$(.venv/bin/python -c 'from auth_utils import nuevo_secreto_totp; print(nuevo_secreto_totp())')"
export TOTP_SECRET

echo "== Arrancando el servidor en https://localhost:$PUERTO_AUTH"
.venv/bin/python servidor_auth.py > servidor_auth.log 2>&1 &
PID=$!
for _ in $(seq 50); do
    curl -s --noproxy localhost --cacert ca.pem "https://localhost:$PUERTO_AUTH/perfil" >/dev/null 2>&1 && break
    kill -0 "$PID" 2>/dev/null || { echo "El servidor no arrancó:"; cat servidor_auth.log; exit 1; }
    sleep 0.2
done

echo
.venv/bin/python cliente_auth.py
```

### Salida real de las pruebas

```
== Funciones de auth_utils
[OK    ] hash Argon2id con sal  ($argon2id$v=19$m=65536,t=3,p=4...)
[OK    ] dos hashes de la misma contraseña son distintos
[OK    ] verifica la contraseña correcta
[OK    ] rechaza la incorrecta
[OK    ] TOTP coincide con el vector del RFC 6238
[OK    ] PKCE S256 coincide con el vector del RFC 7636
[OK    ] PKCE genera un code_verifier de 43 caracteres  (challenge=SNDzuSujyc_h...)

== Sesión con cookie y segundo factor
[OK    ] contraseña incorrecta -> 401
[OK    ] usuario inexistente -> mismo 401 y mismo mensaje
[OK    ] contraseña correcta -> pide segundo factor
[OK    ] cookie con Secure, HttpOnly y SameSite=Lax  (__Host-session=_JXjlK7I_L3k7MX...)
[OK    ] sin segundo factor no hay acceso a /perfil
[OK    ] código TOTP incorrecto -> 401
[OK    ] código TOTP correcto -> sesión completa  (código 866100)
[OK    ] el ID de sesión cambia al autenticar (anti-fijación)
[OK    ] /perfil con sesión  ({"usuario":"juan"})
[OK    ] CSRF: POST desde otro origen -> 403

== Access token JWT y refresh token
[OK    ] se emiten access y refresh token  (alg=ES256, exp-iat=900 s, scope=pedidos:leer)
[OK    ] API sin token -> 401
[OK    ] API con token -> 200  ({"pedidos":[{"id":1,"total":42.5}],"usuario":"juan"})
[OK    ] token con alg=none -> rechazado  (access token no válido: The specified alg val)
[OK    ] token con sub cambiado -> rechazado
[OK    ] refresh -> par de tokens nuevo
[OK    ] reutilizar el refresh antiguo -> 401  (refresh token reutilizado: sesión revocada)
[OK    ] tras la reutilización, toda la familia queda revocada

== Cierre de sesión
[OK    ] logout -> 200
[OK    ] la cookie antigua ya no sirve (sesión borrada en el servidor)

Todo correcto
```

Dos detalles que aparecieron al probarlo:

- **Python 3.13 verifica los certificados en modo X.509 estricto** y rechaza una CA sin la extensión `keyUsage`. Por eso los certificados de los Anexos B y C llevan `keyUsage`, `basicConstraints` y `extendedKeyUsage=serverAuth`. Es la misma comprobación que hacen los navegadores con los certificados reales.
- **`requests` ignora `session.verify` si existe la variable `REQUESTS_CA_BUNDLE`.** El cliente usa `trust_env = False` para usar siempre `ca.pem` y no pasar por proxies del entorno.
