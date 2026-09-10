# Каталог тестов CensorPulse Probe v1

Каждая строка — независимый `test_id`. Все тесты используют один IP и выполняются минимум трижды вместе с baseline и negative control. `P0` обязателен для MVP, `P1` — следующий релиз, `P2` — исследовательский.

| ID | Prio | Transport/port | Клиент → проба | Успех / что различает |
|---|---|---|---|---|
| `tcp.echo.p` | P0 | TCP 80,443,8443,1194,22 | CP1 envelope + random 64/512 B | nonce/hash echo; port reachability и modification |
| `tcp.payload.random` | P0 | те же | random bytes той же длины | negative control для protocol DPI |
| `tcp.rtt` | P0 | TCP | connect + echo RTT, 5 раз | подозрительно быстрый SYN-ACK vs payload RTT; без raw socket лишь сигнал |
| `tcp.segmented` | P1 | TCP 443 | тот же payload одним write и 2–4 writes | sensitivity к segmentation; OS может coalesce, фиксировать limitation |
| `http.host` | P0 | TCP 80,8080,443(clear) | HTTP/1.1 GET с benign/trigger/random Host и nonce path | status/body hash; redirect/block-page/injection |
| `http.case_split` | P1 | TCP 80 | Host case, spacing, header split | fingerprint fragile DPI, не «доступность сайта» |
| `dns.udp` | P0 | UDP 53 | A/TXT synthetic nonce name | signed nonce answer; interception, spoof, drop |
| `dns.tcp` | P0 | TCP 53 | тот же DNS message | UDP-only policy vs DNS-wide |
| `dns.dot` | P0 | TCP 853 | pinned TLS + DNS query | DoT blocking |
| `dns.doh` | P1 | TCP 443/8443 | pinned HTTP/2 POST application/dns-message | DoH/HTTP2 differential |
| `tls.version` | P0 | TCP 443,8443 | TLS 1.2-only / 1.3-only | ServerHello+encrypted nonce exchange |
| `tls.sni` | P0 | TCP 443 | controlled benign / trigger / absent SNI | SNI-dependent failure; cert mismatch отдельно от transport |
| `tls.alpn` | P0 | TCP 443 | h2 / http1.1 / none / unusual ALPN | ALPN policy |
| `tls.fingerprint` | P0 | TCP 443 | uTLS Chrome/Firefox/Safari/iOS/Edge/Android-OkHttp/Go, same SNI/size | ClientHello fingerprint policy; edge/android — контроли «лояльных» паротов |
| `tls.burst` | P0 | TCP 443 | N параллельных ClientHello с одним SNI (chrome / firefox парот) + один с другим SNI + один без SNI, с echo внутри; последним в скане | rate-правило на handshake («сибирская» заморозка): alpha падает, beta проходит |
| `tcp.packets` | P0 | TCP 80, 443(TLS) | конверт tcp.echo по 2 байта с паузой (NODELAY → сегмент на write) | счётчик пакетов на поток (l4-25) против счётчика байт (`tcp.bulk`); контроль — `tcp.echo` |
| `udp.packets` | P0 | UDP 443 | 32 конверта по 32 Б на одном сокете | то же для UDP; контроль — `udp.echo` |
| `tor.handshake` / `tor.link` | P0 | TCP 9001, 443 | tor/OpenSSL ClientHello × relay link cert (4 варианта) + VERSIONS/CERTS/AUTH_CHALLENGE/NETINFO; link = + CREATE_FAST/CREATED_FAST | по какому plaintext-признаку режут vanilla Tor; stateful-обрыв после link-хендшейка |
| `tor.dir` | P1 | TCP 9030, 80 | `GET /tor/status-vote/current/consensus-microdesc.z HTTP/1.0` | DirPort-запрос против http.host |
| `obfs4.handshake` / `obfs4.session` | P0 | TCP 8388, 443 | obfs4-запрос с меткой под identity сервера, паддинг 85–8128 Б; ответ; зеркалирование фреймов | «полностью зашифрованный» трафик obfs4-формы против 64 случайных байт `tcp.payload.random` |
| `stun.binding` | P0 | UDP 3478, 443 | RFC 5389 Binding | STUN как первый шаг WebRTC/Snowflake |
| `dtls.hello` | P0 | UDP 3478, 443 | DTLS 1.2 ClientHello (pion / firefox / chrome) → HVR → ClientHello+cookie → ServerHello | DTLS-fingerprint (Snowflake 2021, 2026-03) против браузерного baseline |
| `tls.record_split` | P1 | TCP 443 | whole vs split ClientHello records/writes | reassembly sensitivity |
| `tls.ech` | P1 | TCP 443 | outer public_name + controlled encrypted inner | ECH-specific blocking vs ordinary TLS |
| `quic.v1` | P0 | UDP 443,8443 | valid QUIC v1 Initial + H3 nonce | QUIC reachability/SNI |
| `quic.v2` | P1 | UDP same | RFC 9369 Initial | version-specific filtering |
| `quic.shape` | P1 | UDP | valid Initial vs same-size random vs short first datagram | QUIC signature/size/stateful first-packet rules |
| `udp.echo` | P0 | UDP 53,443,1194,51820,8443 | cookie + envelope, <=1200 B | generic UDP/port blocking |
| `dtls.12` | P1 | UDP 443,4444 | DTLS 1.2 ClientHello + nonce | DTLS fingerprint vs UDP baseline |
| `openvpn.reset` | P0 | TCP/UDP 1194, TCP 443 | valid P_CONTROL_HARD_RESET_CLIENT_V2 | valid server reset, compared with random/TLS on same port |
| `wireguard.init` | P0 | UDP 51820,443 | authenticated WG initiation | authenticated response; compared with UDP echo same port |
| `wireguard.session` | P0 | UDP 51820,443 | WG handshake + N authenticated transport packets (type 4) both ways | session cut after the handshake; control = `wireguard.init` same port |
| `openvpn.session` | P0 | TCP/UDP 1194, 443 | reset exchange + P_ACK_V1 + N × P_CONTROL_V1 (first = real TLS ClientHello) | session cut after the reset; control = `openvpn.reset` same port |
| `ikev2.init` / `ikev2.session` | P0 | UDP 500, 4500 | IKE_SA_INIT (real X25519 KE) + IKE_AUTH; ESP-in-UDP on 4500 | reachability of IPsec/IKEv2 shape; session cut after IKE_AUTH; control = `ikev2.init` |
| `l2tp.init` / `l2tp.session` | P0 | UDP 1701 | L2TPv2 SCCRQ/ICRQ + PPP data | plain L2TP reachability; session cut; control = `l2tp.init` |
| `socks5.connect` / `socks5.session` | P0 | TCP 1080 | RFC 1928/1929 greeting/auth/CONNECT then mirror | SOCKS5 reachability and auth policy; server never egresses |
| `vless.reality` / `vless.session` | P0 | TCP 443, 4433 | Chrome uTLS + foreign SNI + inner VLESS/TLS-in-TLS | REALITY-shaped SNI/IP-mismatch and TLS-in-TLS reachability; `benign` SNI control |
| `shadowsocks.2022` | P1 | TCP/UDP 8388 | real SS2022 handshake to internal nonce service | full handshake success; never arbitrary proxy egress |
| `vless.reality` | P1 | TCP 4433 | real REALITY+VLESS handshake, fingerprints | SNI/fingerprint/flow differential; local echo only |
| `trojan.tls` | P1 | TCP 4443 | real TLS+Trojan auth then local echo | TLS-in-TLS / protocol policy |
| `hysteria2` | P1 | UDP 2443 | real QUIC-based auth then local echo | Hysteria2 vs ordinary QUIC same port |
| `tuic` | P2 | UDP 3443 | real TUIC auth then local echo | TUIC vs ordinary QUIC |
| `ssh.banner` | P1 | TCP 22,443 | wait banner, then controlled identification | SSH port/protocol policy |
| `ikev2.init` | P2 | UDP 500/4500 | minimal valid IKE_SA_INIT | IPsec port/signature reachability; no tunnel |
| `icmp.echo` | P2 | ICMP | echo nonce | только где API/permissions позволяют; отсутствие ответа inconclusive |
| `throughput.bounded` | P1 | TCP/QUIC | authenticated 1–8 MiB stream | throttling differential; opt-in, strict quota |

## Обязательная последовательность группы

1. Проверить control plane health и listener health snapshot.
2. Зарезервировать attempts.
3. В случайном порядке выполнить baseline, variant, negative control.
4. Получить server observations.
5. Повторить 3 раза с новыми source ports.
6. Классифицировать по `CLASSIFICATION.md`; не сводить разные стадии к одному boolean.

## Что не входит в v1

- raw crafted TCP flags/sequence/TTL и packet fragmentation с телефона;
- полноценный VPN-туннель или выход в Интернет через пробу;
- сканирование чужих адресов;
- attribution конкретному DPI-вендору;
- утверждение о доступности произвольного домена по отрицательному SNI-тесту на нашем IP.

