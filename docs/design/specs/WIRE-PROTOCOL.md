# CensorPulse Probe Protocol v1

Нормативные слова MUST/SHOULD/MAY используются в смысле RFC 2119.

## 1. Модель

Клиент знает IP контрольной точки, встроенный SPKI-пин управляющего сервиса и публичные параметры протокольных тестов. DNS для bootstrap не требуется. Управляющий канал работает по pinned TLS на TCP/8443; TCP/443 остаётся тестовым портом. Если control plane недоступен, клиент возвращает `probe_unreachable`, а не делает вывод о конкретном протоколе.

## 2. Сессия

`POST /v1/session` принимает версию клиента, случайный `client_nonce` (32 bytes), желаемые test IDs и capabilities. Ответ:

```json
{
  "schema_version": 1,
  "session_id": "128-bit random",
  "expires_at": "RFC3339",
  "server_time": "RFC3339Nano",
  "tests": [],
  "token": "opaque authenticated token",
  "udp_cookie": "opaque address-bound cookie"
}
```

Сессия живёт не более 10 минут. Token подписан сервером и связывает session, expiry, разрешённые тесты и лимиты. UDP cookie дополнительно связан с наблюдаемым source IP. Клиент не принимает секреты от оператора; доверие задаётся пином, встроенным при сборке.

## 3. Test envelope

Где формат позволяет, payload содержит magic `CP1`, `session_id`, `test_id`, 96-bit nonce, monotonic sequence, payload length и HMAC/token proof. Ответ MUST повторить test ID, nonce, SHA-256 принятого payload, длину и серверные timestamps `seen_at/replied_at`.

Для нативных wire formats, куда envelope не помещается (TLS ClientHello, OpenVPN reset, WireGuard initiation), корреляция делается временным reservation через control plane: клиент запрашивает одноразовый `attempt_id`, порт/вариант и окно 15 секунд. Сервер связывает ближайший подходящий flow с attempt по source IP, порту, fingerprint и времени.

## 4. Серверный результат

`GET /v1/session/{id}/observations` возвращает только результаты текущей сессии:

```json
{
  "attempt_id":"...", "test_id":"tls.sni.blocked.v1",
  "transport":"tcp", "dst_port":443,
  "server_seen":true, "first_seen_at":"...", "bytes_in":517,
  "payload_sha256":"...", "parse":"valid_client_hello",
  "response":"server_hello", "bytes_out":231,
  "close":"normal", "server_error":null
}
```

Хранить payload целиком нельзя; только фиксированные разобранные поля, длины и hashes. IP клиента в выдаче не нужен и в постоянное хранилище не пишется.

## 5. Тайминг

Клиент пишет wall clock и monotonic timestamps для DNS/connect/first-write/first-byte/close. Сервер пишет receive/reply monotonic deltas. Межхостовое сравнение абсолютного времени используется только после оценки clock offset по минимуму из 5 control RTT; классификатор не требует точной синхронизации.

## 6. Повторы

Одна группа: baseline, variant, negative control. Минимум 3 попытки каждого типа, новые source ports, псевдослучайный порядок, jitter 250–1250 ms. Stateful/residual censorship проверяется отдельной группой с паузами 5/30/120/420 s; обычный scan не переиспользует 4-tuple.

