# Спецификация Docker-пробы v1

## Компоненты

- `control-api`: pinned TLS TCP/8443, session/token/observation API.
- `dispatcher`: TCP/UDP listeners, корреляция attempts и bounded echo.
- `protocol-workers`: TLS/HTTP/DNS/QUIC/OpenVPN/WireGuard и изолированные real protocol adapters.
- `observation-store`: in-memory/SQLite ring buffer, TTL 24 h максимум.
- `health`: локальные readiness checks каждого listener и экспорт метрик без client payload.

Рекомендуемый язык ядра — Go. uTLS нужен для клиентского CLI, quic-go — для QUIC/H3. Сложные VPN workers допустимо запускать отдельными контейнерами (sing-box/xray/OpenVPN/WireGuard userspace), но наружу они отдают только внутренний nonce service.

## Сеть и порты

На Linux нужен `network_mode: host`: Docker userland proxy/NAT меняет timing и мешает нескольким TCP/UDP listeners. Минимальный ingress: TCP 80,443,8443,1194; UDP 53,443,1194,51820,8443; TCP 53/853 для DNS. Расширенные worker ports — из `TEST-CATALOG.md`. Все listeners dual-stack, если у хоста есть IPv6; результаты IPv4/IPv6 раздельны.

Контейнеры работают non-root. Для портов <1024 выдаётся только `CAP_NET_BIND_SERVICE`; `CAP_NET_RAW` ядру v1 не нужен. Root capture sidecar — опциональный debug-профиль, выключен в production.

## Запрет open proxy/reflection

- egress workers запрещён firewall-ом, кроме loopback/internal service и явно нужных обновлений вне runtime;
- никакого CONNECT/SOCKS/general DNS recursion;
- UDP до address validation: response <= request и максимум 256 B; после cookie — <=1200 B;
- TLS amplification ограничить короткой цепочкой сертификата, rate limits и SYN cookies ОС;
- per-IP: 10 session/min, 120 attempts/10 min, throughput test 16 MiB/day по умолчанию;
- session token разрешает только конкретные test IDs и истекает через 10 min;
- ответы не направляются на адрес/порт, отличный от источника пакета;
- malformed/native handshakes получают минимум данных или молчание, но observation сохраняется.

## Privacy и логи

Постоянно хранить только агрегаты. Session observations удалять через 24 h; source IP — HMAC с суточной rotating key либо не хранить после закрытия сессии. Не логировать полные payload, SNI trigger catalogs, auth material и packet captures по умолчанию. Debug pcap требует явного оператора, короткого окна и автоудаления.

## Конфигурация

Единственный versioned YAML: schema version, bind addresses, enabled tests, ports, SPKI key refs, signing key refs, quotas, retention. Секреты — files/secret store, не environment dump и не image. Startup MUST fail closed при конфликте портов, отсутствии ключа или невозможности поставить egress deny rules.

## Observability

Метрики: attempts по test/outcome, listener health, parse failures, rate-limit drops, response bytes/request bytes, clock offset, CPU/memory/fd. Никаких labels с IP/session/SNI. `/healthz` локальный; публичный health входит только в authenticated control API.

## Definition of done Этапа 2

1. `docker compose up` на чистом Ubuntu arm64/amd64 поднимает P0 listeners.
2. CLI по одному IP проходит весь P0 catalog и получает client+server evidence.
3. Unit tests покрывают envelope/parser/classifier; integration tests эмулируют drop/RST/modify/delay.
4. Egress test доказывает, что пробу нельзя использовать как proxy или recursive resolver.
5. UDP amplification factor до validation <=1, после validation bounded.
6. Контрольная точка в ЕС↔таргет и RU-cloud↔таргет дают совпадающий clean baseline.
7. Report JSON стабилен, versioned и содержит raw attempts + derived verdicts.

