# Prior art: hyperion-cs/dpi-checkers (разбор 2026-09-12, commit 58769ee, dpich v0.8.x)

Go-утилита `dpi-ch` (Apache-2.0) + браузерные чекеры + утилиты на Python.
Автор — тот же, кто описал tcp 16-20 / l4-25 (net4people/bbs#490) и
«сибирскую» блокировку (habr 1044396). Как и dpi-detector, это клиент без
своего сервера: «правда» берётся из чужих хостов, найденных динамически.

## Что делает

| Чекер | Механика | Оценка для cpprobe |
|---|---|---|
| whoami | внешний IP через Yandex/RIPE API, затем ASN/org/country офлайн из GeoLite2-CSV (Loyalsoldier/geoip) | схема «IP → ASN офлайн» решает п.3 роадмапа (carrier/ASN в отчёте) без egress |
| cidrwhitelist | параллельные HEAD к «белым» (ya.ru, vk.ru, max.ru) и «обычным» (github, wikipedia, google) URL: обычные недоступны, белые доступны → сеть под CIDR-whitelist | вне модели «один свой IP», но как `warning` о контексте сети имеет смысл |
| webhost: alive | uTLS-handshake + HEAD; при провале handshake пробует SNI `cf.com`/`google.com` на том же IP → «blocked by SNI» | у нас уже есть (benign/trigger/absent SNI на своём IP) |
| webhost: tcp1620 | **новый метод**: не скачивать, а заливать 64 КБ POST в keep-alive-соединении; исходящий поток режется так же, как входящий | у нас `tcp.bulk up/down` уже так устроен |
| webhost: siberian | 4 параллельных TLS-handshake с Chrome-fingerprint и одним случайным SNI (alpha) + 1 handshake с другим SNI (beta). alpha упала, beta прошла → «siberian». Если сервер ругается на случайный SNI (`tls: internal error`) — повтор с настоящим SNI и пустым | **нет у нас**: stateful-правило поперёк соединений, наш каталог тестирует по одному соединению |
| dns | plain к 15 провайдерам + DoH к ~10; spoofing = ответ вне subnetfilter'а (`org("google")`); hijacking = A-запись `whoami.akamai.net` не из подсети провайдера; DoH bootstrap через системный резолвер и проверка, что IP DoH-хоста «свой»; leak = случайная метка `.dns4.browserleaks.net` | у нас `dns.system` + whoami TXT в своей зоне даёт то же без Akamai/browserleaks; DoH-bootstrap-spoofing как идея переносима на наш control-хост |
| subnetfilter + webhostfarm | цели не фиксированы: выражение `org("hetzner") && country("de")` → набор подсетей (expr-lang + netipx) → случайные IP, у которых удаётся TLS-handshake | защита от «цензор внёс наш список в whitelist»; нам не нужна — цель одна и своя |
| utils/l4-25_prober.py | 64 байта POST'а по 2 байта с TCP_NODELAY и паузой 50 мс → 32+ пакета при ~64 байтах; если ответа нет — считают **пакеты**, не байты | дешёвый дискриминатор «счётчик пакетов vs байтов», у нас его нет |
| utils/tcp1620_prober.py | матрица {Host: host/ip/fake/none} × {SNI: host/fake/none} × {TLS 1.2/1.3/plain} × {443/80} для одного хоста; «wfb» = ждёт ли сервер тело | матрица SNI×Host×версия у нас размазана по тестам, но покрыта |
| tcp-16-20_dwc | брутфорс SNI-whitelist: top-10k OpenDNS через свой сервер в «подозрительной» сети, 266 доменов бело (2025-07); правило `*.domain:*` — поддомены тоже белые | список = стартовый `--sni-list`; факт про поддомены стоит учесть в интерпретации |

## Факты о цензоре, которых у нас в CLASSIFICATION нет

1. **l4-25**: замораживание не по байтам, а по числу пакетов в любую сторону,
   обычно 25 (≈16 КБ payload). Касается и TCP, и UDP. Whitelist по SNI/Host
   и отдельно по CIDR назначения.
2. **«Сибирская» (июнь 2026)**: ClientHello оценивается по трём признакам —
   подозрительный IP/AS (в т.ч. РФ-ДЦ: Selectel, Yandex Cloud, Cloud.ru),
   подозрительный fingerprint (Chrome, Safari, iOS; Firefox/Android-OkHttp/
   Edge/360/QQ проходят), >3 параллельных handshake с одним SNI за ~350–400 мс
   в окне 60 с → заморозка 120 с всех TLS к этому IP+SNI (TCP-коннект
   проходит, ServerHello может дойти). Пустой SNI не триггерит. Смена
   fingerprint во время заморозки давала +600 с (в июне убрали). HTTP/1.1 и
   HTTP/2, TLS 1.2 и 1.3, любой порт — без разницы.

## Статус переноса (2026-09-12)

Сделано: 1 (`tls.burst`), 2 (`tcp.packets`, `udp.packets`; сервер атрибутирует
недосланный конверт по заголовку и reservation), 3 (edge/android в плане,
360/qq доступны), 4 (`internal/geoip`, `scripts/geoip-update.sh`,
`--geoip-dir`, поле `network` в отчёте), 6 (`lists/sni-allowlist-ru-2025-07.txt`,
`--sni-sample`). Не делал: 5 (детализация alert'ов — `detail.alert` уже
хранит текст), 7 (DoH-bootstrap: наш DoH идёт по IP), 8 (cidr-whitelist
warning: единственный тест с чужими хостами, ждёт решения). Ничего из этого не
гонялось против живого DPI — только интеграционные тесты с fault-proxy.

## Что взять (по убыванию ценности)

1. **`tls.burst` — тест «сибирской» заморозки на своём IP (P1).** N=4
   параллельных ClientHello (chrome-парот) с одним случайным SNI, контроль:
   1 handshake с другим SNI сразу после и 1 handshake с пустым SNI. Матрица
   исходов: alpha timeout / beta ok → `tls_burst_freeze`; оба timeout →
   inconclusive (путь лёг). Обязательно: запускать **последним** в скане и с
   SNI, который больше нигде не используется, иначе 120-секундная заморозка
   отравит остальные TLS-тесты к нашему IP. Второй вариант с `firefox`-паротом
   даёт ось «fingerprint-зависимость». Сервер уже умеет считать observations
   по SNI, ничего нового на сервере не нужно.
2. **`tcp.bulk` вариант `packets`** (P1, дёшево): 64 байта по 2 байта с
   `TCP_NODELAY` и паузой 50 мс на нашем echo. Обрыв → `l4_packet_counter`,
   прошло, а 64 КБ режется → `l4_byte_counter`. Плюс `udp.bulk`: 40 датаграмм
   по 32 байта в `udp.echo` с cookie; фиксировать номер, на котором эхо
   пропало. Закрывает «касается и UDP» из п.1.
3. **Fingerprint-набор**: добавить `edge`, `android` (OkHttp), опционально
   `360`, `qq` из uTLS — это «лояльные» пароты по наблюдениям автора, они
   превращают `tls.fingerprint` из «блокируют ли Chrome» в «по какому
   признаку». `HelloEdge_85`, `HelloAndroid_11_OkHttp`, `Hello360_7_5`,
   `HelloQQ_11_1` есть в utls. Заодно фиксировать в отчёте, что uTLS
   `randomized` сломан на key share — dpi-ch его тоже не использует.
4. **ASN/страна клиента офлайн**: GeoLite2-ASN/Country CSV из
   Loyalsoldier/geoip, обновляемые с релизами (у них — updater раз в сутки).
   Для нас: клиент получает `client_public_addr` из `/v1/session`, маппит
   локально в ASN/org/country, кладёт в `report.network`. Сервер не ходит
   наружу, модель не ломается. Это п.3 роадмапа.
5. **Классификатор alert'ов**: у них по строкам `handshake failure`,
   `internal error`, `bad record MAC`, `invalid server key share`; у нас
   `tls_alert` без детализации. Разложить на `tls_alert_<desc>` — `bad record
   MAC` после ServerHello на нашем IP означает подмену записей на пути.
6. **Стартовый `--sni-list`**: `ru/tcp-16-20_dwc/results/based_on_opendns_2025-07-02.txt`
   (266 доменов, столбцы Domain/Provider/Country). Учесть, что whitelist
   разный у операторов и включает поддомены.
7. **DoH-bootstrap spoofing**: резолвить имя нашего control-хоста системным
   резолвером и сверять с pinned IP — ловит подмену A-записи на пути к DoH.
   У нас DoH идёт по IP, поэтому этой проверки нет; она дешёвая.
8. **Контекст сети как warning** (опционально, RU-специфично): три HEAD к
   «белым» и три к «обычным» хостам перед сканом; `cidr_whitelist_network`
   в `warnings`, если живы только белые. Единственное место, где клиент
   ходит не на наш IP; держать за флагом.

## Что не брать

- subnetfilter/webhostfarm/динамические цели: расходится с моделью «один
  свой IP» и анти-abuse.
- Сеть чужих DNS-провайдеров (15 plain + 10 DoH), Akamai-whoami,
  browserleaks-leak: у нас всё это закрывает своя зона.
- TUI на bubbletea, self-updater, Yandex/RIPE-API для внешнего IP.
- Web-чекеры (ограничены sandbox'ом браузера; для мобильного клиента
  Этапа 3 неприменимы).
