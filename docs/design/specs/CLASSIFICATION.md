# Классификация результатов v1

## Низкоуровневые исходы

- `ok`: ожидаемый nonce/hash подтверждён клиентом и сервером.
- `connect_timeout`: TCP SYN не привёл к соединению до deadline.
- `connect_refused`: локально получен ECONNREFUSED/ICMP port unreachable.
- `connect_reset`: RST до первого application write.
- `payload_timeout`: connect успешен, payload отправлен, ответа нет.
- `midstream_reset`: RST после первого application write.
- `tls_alert`: получен корректный TLS Alert; хранить level/description.
- `tls_parse_failure`: полученные bytes не являются ожидаемым TLS ответом.
- `cert_mismatch`: TLS дошёл до Certificate, но cert/pin не тот.
- `quic_no_response`, `quic_vn`, `quic_retry`, `quic_handshake_failure`.
- `dns_timeout`, `dns_rcode`, `dns_answer_mismatch`, `dns_injected_race`.
- `modified`: серверный hash принятого payload или клиентский hash ответа отличается.
- `injected`: клиент получил ответ, который сервер не отправлял, либо получил его раньше, чем сервер увидел запрос.
- `session_cut`: VPN-хендшейк завершён, но data/control-пакеты после него перестали приходить (`data_recv` из `data_sent`, `data_first_loss`). Оборванный поток (FIN/RST), когда не вернулся ни один data-пакет, — тоже cut; форма обрыва в `data_close`, потому что на TCP путь, глотающий туннельные пакеты, оставляет пира в простое, и тот вешает трубку раньше, чем клиент исчерпает свои таймауты.
- `packets_cut`: поток мелких пакетов перестал получать ответы (`packets_sent`/`packets_acked`, `first_loss`, `server_packets_seen`).
- `burst_freeze`: часть из N параллельных handshake к одному SNI упала, одиночный handshake к другому SNI сразу после — прошёл (`alpha_ok`, `beta_outcome`, `gamma_outcome`, `server_alpha_seen`).
- `server_error`: контрольная точка сама не смогла выполнить тест; не цензура.
- `inconclusive`: доказательств недостаточно.

## Слияние client + server evidence

| Клиент | Сервер видел запрос | Сервер отправил ответ | Итог |
|---|---:|---:|---|
| timeout | нет | нет | `uplink_drop_or_route_failure` |
| connect_timeout | принял пустое соединение с адреса клиента в окне reservation | нет | `connect_diverged_middlebox_or_misattributed` — клиент handshake не завершил, «молчать» серверу было не на чем |
| timeout | да, но уже после дедлайна клиента (`server_delay_ms` > `done` + 1 с) | любой | `uplink_delayed_past_deadline` — запрос дошёл поздно (потеря + ретрансмит или удержание на пути), обратно ничего не терялось |
| timeout | да | да (любые байты, в т.ч. ServerHello без ответа клиента) | `downlink_drop` |
| timeout | частично; сервер ждал остаток и получил timeout/EOF | нет | `uplink_drop_or_route_failure` |
| RST | нет/да | RST не слал | `rst_injected_or_path_reset` |
| неожиданный ответ | нет | нет | `injected` |
| hash mismatch | да | ожидаемый hash | `downlink_modified` |
| серверный hash не совпал | да | любой | `uplink_modified` |
| timeout | да | нет, собственная ошибка сервера | `server_error` |
| quic handshake по дедлайну | нет / видел Initial | — | `uplink_drop_or_route_failure` / `stalled_after_server_saw_it` (форвардер считает только вход, направление потери неизвестно) |

Приоритет строк: «сервер отправил байты» бьёт «server error» — ошибка чтения после отправленного ServerHello это закрывшийся по таймауту клиент, а не вина сервера. `downlink_modified` только при реальном расхождении хеша/криптографии, не по таймауту.

Без серверного observation `packet_drop` не выставляется: только `timeout_observed`.

## Шум скана

Всплеск сбоев на несвязанных портах и семействах (≥ 6 попыток на ≥ 3 портах за 20 с), чьи ячейки в остальных раундах проходят — обрыв сети у клиента (радио, маршрут, NAT-ребайнд), не правило. Такие попытки помечаются `detail.transient=true`, из ячеек исключаются, окно описывается в `notes`. Сбои в ячейках, которые падают стабильно, никогда не помечаются.

Клиент за NAT (сервер видит другой source port, чем клиент привязал) — для `ikev2.*` / `l2tp.*` вердикт не выше `medium`: ALG на NAT из одной точки от цензора не отличить.

## Дифференциальные вердикты

- `port_blocking_suspected`: один payload проходит на control port, но стабильно не проходит на test port; оба listener healthy; при этом на test port не проходит **ничего**.
- `transparent_proxy_suspected`: echo/random на порту не проходят (сервер их видел и ответил, ответ не дошёл), а распознаваемый протокол (HTTP/TLS/DNS) на том же порту проходит — путь ретранслирует только то, что умеет парсить. Не блокировка порта.
- `synack_local_termination_suspected`: медианный TCP connect на порту меньше четверти медианы по остальным портам (и короче на ≥20 мс) — SYN-ACK отдаёт middlebox. `medium`, если `tcp.rtt` на том же порту согласен или на том же порту есть `transparent_proxy_suspected` (тот же middlebox с другой стороны).
- `wireguard_session_cut_suspected` / `openvpn_session_cut_suspected`: handshake-тест на порту проходит, session-тест (те же handshake + N data/control пакетов) — нет. Сигнатура stateful-блокировки «хендшейк есть, трафика нет»; evidence — медианы отправлено/получено/увидел сервер и направление потери. У OpenVPN между reset и туннелем есть control-канал, поэтому evidence называет, что именно срезано: «control channel passed …, data channel cut» — это путь, который пропускает TLS-хендшейк и PUSH_REPLY и убивает туннель (реальный клиент такое видит как `KEEPALIVE_TIMEOUT` после успешного коннекта); «the control channel itself was cut right after the reset» — срезано раньше. Варианты `tls-auth` и plain считаются отдельными ячейками: правило DPI может смотреть на сигнатуру заголовка control-канала.
- `protocol_blocking_suspected`: baseline/random на том же port проходят, валидный wire fingerprint нет.
- `fingerprint_blocking_suspected`: один ClientHello/QUIC fingerprint не проходит, другой с теми же IP, SNI, port и близким размером проходит.
- `sni_or_host_blocking_suspected`: trigger SNI/Host не проходит, controlled benign SNI/Host проходит на том же IP/port.
- `udp_blocking_suspected`: TCP controls проходят, несколько UDP families с cookies не достигают сервера; отдельно от QUIC-only/WG-only.
- `packet_count_cut_suspected`: `tcp.packets`/`udp.packets` падают, а однопакетный echo на том же порту проходит — лимит считается в пакетах; evidence сверяет с `tcp.bulk` на том же порту (упал тоже → правило пакетное, прошёл → срабатывает только на россыпь мелких пакетов).
- `tls_burst_freeze_suspected`: `tls.burst` даёт `burst_freeze` в большинстве раундов; confidence от baseline `tls.sni benign` на порту; evidence говорит, сколько hello сервер видел / ответил / получил обрезанными, и прошёл ли тот же burst с другим паротом (правило зависит от fingerprint) или нет. Нота о «заморозке адреса на минуты» ставится только если одиночные handshake после burst тоже упали; иначе нота говорит, что дропнут сам burst.
- `tor_handshake_blocking_suspected`: вариант `tor.handshake` падает при проходящем `go-hello+probe-cert` на том же порту; evidence по двум однопризнаковым вариантам называет признак (ClientHello, сертификат, только оба вместе).
- `tor_session_cut_suspected` / `obfs4_session_cut_suspected`: handshake проходит, data-фаза нет (как VPN-сессии).
- `dtls_fingerprint_blocking_suspected`: парот `pion`/`chrome-136` в `dtls.hello` падает при проходящем `firefox-138` на том же UDP-порту.
- `dns_port_blocking_suspected`: семейство `dns.*` падает на порту без echo-теста (53/853), при проходящем echo того же транспорта на другом порту.
- `throttling_suspected`: sustained transfer статистически ниже baseline на том же пути и размере, при нормальных RTT/loss controls.

Правила против ложных срабатываний (ревизия 2026-09-12):
- потеря пакетов — не обрыв: `session_cut` / `packets_cut` только когда обмен закончился тремя неотвеченными подряд; `burst_freeze` только когда упала хотя бы половина параллельных handshake;
- `protocol_blocking_suspected` — один вердикт на семейство и порт; session-тест при упавшем handshake-тесте отдельно не считается;
- если baseline семейства упал, а другой вариант прошёл, контролем становится прошедший вариант (chrome заблокирован, edge проходит);
- merged-результаты `rst_injected_*`, `*_modified`, `injected` для ячеек, уже названных дифференциальным вердиктом, прикрепляются к нему строкой `mechanism:`; самостоятельно — не выше `medium`;
- попытки с одним reservation-пулом (transport/port/kind) на клиенте не выполняются одновременно, чтобы сервер привязывал поток к нужному окну.
- `endpoint_blocking_suspected`: все payload families после connect падают одинаково, тогда как контрольная vantage проходит.

## Confidence

- `high`: 3/3 variant failures, 3/3 paired controls ok, server evidence однозначно локализует направление.
- `medium`: 2/3 или нет server observation, но повторяемый differential есть.
- `low`: одиночный timeout/RST, меняющаяся сеть, control degradation или неизвестная серверная ошибка.

`summary` считает `high` и `medium`; `low` перечисляются отдельно после `low confidence:`.

Финальный report MUST сохранять raw attempts. Вердикт не должен скрывать неоднозначность. Публичные формулировки: «наблюдается поведение, совместимое с …», а не «оператор использует DPI X».

