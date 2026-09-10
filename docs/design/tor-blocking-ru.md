# Как в России блокируют Tor и что из этого измеряет cpprobe (2026-09-12)

Сводка по открытым источникам на сентябрь 2026 и привязка к тестам пробы.
Проба никогда не ходит в сеть Tor: оба конца наши, измеряется только то,
как путь реагирует на форму трафика.

## Хронология и механики

| Когда | Что блокируют | Механика | Источник |
|---|---|---|---|
| 2021-12 | Directory authorities, публичные relay, встроенные obfs4-мосты, meek-фронт `ajax.aspnetcdn.com` | IP-блок на ТСПУ: SYN без ответа (Yota, Tele2, МТС, Билайн, Мегафон, Ростелеком); UDP/ICMP к тем же IP проходят | ntc.party/t/1477, net4people/bbs#97, OONI 2021-12 |
| 2021-12 | Snowflake | DTLS-fingerprint pion: сначала `supported_groups` в ServerHello (баг pion), потом смещение `supported_groups` в ClientHello; соединение рвётся после нескольких КБ | ntc.party/t/1477 p.2, Bocovich et al. USENIX Sec 2024 §5.1 |
| 2022-11 | meek-azure | IP/SNI-блок фронта `ajax.aspnetcdn.com` | ntc.party |
| 2024-06 | obfs4-мосты из BridgeDB/Moat/email | РКН автоматически собирает раздаваемые мосты и блокирует по IP; частные мосты живут; часть провайдеров режет obfs4 как «полностью зашифрованный» трафик (бутстрап встаёт на 10–25 %, «TCP retransmission» в Wireshark) | ntc.party/t/8006, /t/14188, /t/19048 |
| 2024-11 | Snowflake | DTLS-хендшейк проходит, несколько байт данных приходят, дальше клиент перестаёт получать: не fingerprint 2021, похоже на stateful-обрыв | net4people/bbs#422 |
| 2025 → | obfs4/WebTunnel-мосты на Hetzner, OVH, Cloudflare, Oracle, AWS и др. | не Tor-специфично: 16–20 КБ / l4-25 и CIDR-whitelist по хостерам (см. prior-art-dpi-checkers.md) | forum.torproject.org/t/21053, /t/21105 |
| 2026-03-30 | Snowflake | ТСПУ рвёт DTLS-соединения с конкретным JA3/JA4 ClientHello после небольшой задержки; `random-and-mimic` fingerprint проходит; брокер за `.net`-SNI доступен | net4people/bbs#603 |

Отдельно: `torproject.org` в реестре РКН с 2021-12 (DNS/SNI-блок), приложения
убирают из сторов, WebTunnel-мосты, не попавшие под хостер-блок, работают.

## Что видит DPI в vanilla Tor

- **ClientHello**: без SNI, список шифров `ciphers.inc` (копия Firefox:
  c02b c02f cca9 cca8 c02c c030 c00a c009 c013 c014 009c 009d 002f 0035 плюс
  TLS 1.3 1301 1303 1302 и SCSV 00ff в конце), без session ticket
  (`SSL_OP_NO_TICKET`), без ALPN, OpenSSL-набор signature_algorithms (с
  ed448 и DSA). Именно ALPN и ed448 отличают его от Firefox без SNI. Проба
  воспроизводит форму OpenSSL 3.0; tor, слинкованный с OpenSSL 3.5+, ещё
  предлагает X25519MLKEM768 первым и гибридный key_share — это не
  воспроизведено.
- **Сертификат relay** (виден только в TLS 1.2, в 1.3 зашифрован): link-ключ
  RSA-2048, подписан identity-ключом RSA-1024, subject
  `www.<8–20 base32>.com`, issuer `www.<…>.net`, срок 5–365 дней с началом в
  случайную полночь (tor `src/lib/tls/tortls.c`, `x509.c`). Поэтому четыре
  основных варианта `tor.handshake` идут по TLS 1.2 (оба признака на
  проводе), а `@1.3` — современная форма, где виден только ClientHello.
- **Link-протокол**: VERSIONS (circid 2 байта, cmd 7) → CERTS (129),
  AUTH_CHALLENGE (130), NETINFO (8) → CREATE_FAST/CREATED_FAST (5/6) по 514
  байт.
- **DirPort**: `GET /tor/status-vote/current/consensus-microdesc.z HTTP/1.0`.

## Тесты cpprobe

| Тест | Порт | Что измеряет | Контроль |
|---|---|---|---|
| `tor.handshake` | 9001 (и 443 для полной формы) | TLS-хендшейк + VERSIONS/CERTS/AUTH_CHALLENGE/NETINFO. Варианты `go-hello+probe-cert` (baseline), `go-hello+tor-cert`, `tor-hello+probe-cert`, `tor-hello+tor-cert` разводят два plaintext-признака | baseline на том же порту; evidence называет признак |
| `tor.link` | 9001 | то же + N раундов CREATE_FAST/CREATED_FAST | `tor.handshake` (stateful-обрыв после хендшейка) |
| `tor.dir` | 9030, 80 | директорный запрос, ответ в форме консенсуса | `http.host` / echo на порту |
| `obfs4.handshake` / `.session` | 8388, 443 | клиентский запрос с меткой под identity сервера, паддинг 85–8128 Б; ответ с меткой; зеркалирование фреймов | `tcp.payload.random` (64 Б случайных) на том же порту: отличает «режут любой мусор» от «режут мусор obfs4-размера» |
| `stun.binding` | 3478, 443 | RFC 5389 Binding, ответ XOR-MAPPED-ADDRESS | echo на порту |
| `dtls.hello` | 3478, 443 | ClientHello → HelloVerifyRequest → ClientHello+cookie → ServerHello; пароты `pion` (Snowflake), `firefox-138` (baseline), `chrome-136` | baseline = браузерный парот; `dtls_fingerprint_blocking_suspected` |

Сервер: сертификат выбирается по pending reservation tor.* (варианты
`+tor-cert`/`+probe-cert`) или по форме ClientHello; relay-cert генерится при
старте и пинится через `tor_spki_pin` в `/v1/params`; obfs4-identity
(`obfs4_cert`) хранится в data dir; DTLS-cookie stateless (HMAC от адреса);
STUN и DTLS отвечают только под reservation.

## Что не покрыто

- IP-блоки реальных relay/мостов и `torproject.org`: у пробы один свой IP,
  это не её вопрос (OONI `tor`-тест закрывает).
- Настоящий ntor/Elligator2 и шифрование obfs4 после хендшейка: форма и
  размеры воспроизведены, крипто нет; DPI без ключей моста разницы не видит.
- Полный DTLS-хендшейк (Certificate/KeyExchange/Finished): правила
  2021/2026 срабатывают на ClientHello/ServerHello, дальше не идём.
- Snowflake-рандеву через домен-фронтинг (broker за CDN): чужие хосты.
