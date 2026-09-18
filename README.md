# ASTRYM

**Open Source OSINT utility — 20+ команд, 50+ источников, REST API, STIX 2.1, граф инфраструктуры.**

Работает на Android (Termux), Linux, macOS, Windows. 80% функционала — без API-ключей.

[![Python](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

---

## Возможности

| Команда | Что делает |
|---|---|
| `ip <addr>` | WHOIS, GeoIP (4 источника), 11 DNSBL, ASN, extended sources, consensus |
| `domain <domain>` | DNS-записи, WHOIS, RDAP, CT-логи, поддомены, consensus |
| `dns <domain>` | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV + DNSSEC |
| `sub <domain>` | crt.sh + brute-force + 7 пассивных источников + permutation |
| `email <addr>` | MX, SMTP, Gravatar, HIBP, XposedOrNot, PGP, MTA-STS |
| `check <target>` | VirusTotal, GreyNoise, URLhaus, ThreatFox, OTX → risk score 0..100 |
| `ssl <domain>` | Сертификат, SAN, HSTS, устаревшие TLS |
| `scan <target>` | Автоопределение типа + полный прогон |
| `web <domain>` | CMS, открытые пути, wildcard detection, favicon hash, analytics |
| `takeover <domain>` | Subdomain takeover по 20 сигнатурам |
| `leak <domain>` | GitHub + paste dorks (15 сайтов × 15 паттернов) |
| `origin <domain>` | Настоящий IP за Cloudflare |
| `whois-history <domain>` | Timeline WHOIS через RDAP + crt.sh |
| `darkweb <.onion>` | Tor crawl, извлечение email / телефонов / BTC |
| `phone <+num>` | Оператор, регион, мессенджеры, Google Dorks |
| `asn <AS15169>` | ASN discovery через RIPE Stat + диск-кэш |
| `cname <domain>` | Цепочка CNAME (hops) |
| `ahmia <query>` | Поиск .onion через Ahmia (без Tor) |
| `consensus <ip>` | Multi-source голосование (достоверность данных) |
| `timeline <target>` | Изменения цели во времени (diff snapshots) |
| `monitor <target>` | Фоновый watch с алертами |
| `related <target>` | Связи в графе (BFS, N шагов) |
| `correlate <t1> <t2>` | Общая инфраструктура между целями |
| `community` | Louvain-скопления в графе |
| `gexf <out.gexf>` | Экспорт в Gephi / Cytoscape / yEd |
| `stix <target>` | STIX 2.1 bundle для MISP / OpenCTI |
| `watch <target>` | Снапшот + diff |
| `push <target>` | Экспорт в `/sdcard/astrym-drop/` (AFFiNE) |

---

## Установка

### Termux (Android)

```bash
pkg update && pkg upgrade
pkg install python dnsutils curl git
pip install dnspython requests rich networkx reportlab phonenumbers
```

Linux / macOS

```bash
git clone https://github.com/mosadov/Astrym.git
cd Astrym
pip3 install -r requirements.txt
```

Проверка

```bash
python3 astrym.py selfcheck
```

---

Быстрый старт

```bash
# интерактивное меню
python3 astrym.py

# один домен
python3 astrym.py domain github.com

# IP со всеми источниками + все форматы файлов
python3 astrym.py ip 8.8.8.8 -x -f all

# threat intel
python3 astrym.py check 1.1.1.1

# ASN
python3 astrym.py asn AS15169

# граф: Louvain-сообщества
python3 astrym.py community

# экспорт STIX
python3 astrym.py stix github.com -f all
```

---

Consensus engine

Мнения всех источников нормализуются и голосуются. По каждому полю — уровень достоверности:

```
Consensus (multi-source)
  country    us                            confirmed (4/4)
  city       mountain view                 likely (2/3)
  isp        google                        confirmed (3/4)
  asn        AS15169                       confirmed (4/4)
```

Уровень Условие
confirmed ≥3 источника и ≥60% согласия
likely ≥2 источника и ≥50% согласия
single только 1 источник
weak согласие <50%
conflict нет большинства
anycast public-DNS IP (8.8.8.8, 1.1.1.1 и др.)

Для anycast-IP city/region/timezone автоматически помечаются как anycast — один адрес физически существует в десятках дата-центров.

---

Форматы вывода

Формат Файл
json results/<kind>/<kind>N.json
html results/<kind>/<kind>N.html
csv results/<kind>/<kind>N.csv
pdf results/<kind>/<kind>N.pdf
md results/<kind>/<kind>N.md (AFFiNE / Obsidian)
topology results/<kind>/<kind>N_topology.html (vis.js)
stix results/stix/<target>_bundle.json
all всё сразу

```bash
python3 astrym.py domain github.com -f all
```

---

Граф инфраструктуры

Все сканы кладутся в SQLite (~/.astrym/graph/astrym.db).

· related <target> — узлы за N шагов
· correlate <t1> <t2> — общие NS / ASN / registrar / cert_issuer
· community — Louvain-сообщества
· gexf — экспорт для Gephi
· timeline — изменения во времени

```bash
python3 astrym.py domain github.com
python3 astrym.py domain gitlab.com
python3 astrym.py correlate github.com gitlab.com
python3 astrym.py community
```

---

REST API

Сервер на голом http.server, ноль зависимостей.

```bash
python3 astrym_serve.py --genkey       # сгенерировать API-ключ
python3 astrym_serve.py --host 0.0.0.0 # запустить
```

Эндпоинты

Метод Путь
GET /health
GET /info
GET /kinds
GET /scan/<kind>/<target>?format=json\|md\|html\|stix
POST /batch

```bash
KEY=$(python3 astrym_serve.py --list-keys | head -1)

curl -H "X-API-Key: $KEY" http://127.0.0.1:8080/scan/domain/github.com
curl -H "X-API-Key: $KEY" 'http://127.0.0.1:8080/scan/ip/8.8.8.8?format=md'
```

---

STIX 2.1 export

Собственный writer, без библиотеки stix2. Собирает bundle для MISP / OpenCTI / TheHive.

```bash
python3 astrym.py stix github.com -f all
```

Импорт:

· MISP: Administration → Feeds → Import → STIX 2.1
· OpenCTI: Data → Import → STIX 2.1 bundle
· TheHive: Templates → STIX → Upload

---

Профили интенсивности

Параметр --stealth normal --aggressive
Пауза между запросами 3.0s 0.4s 0.05s
HTTP timeout 30s 10s 5s
Воркеры 8 40 150

```bash
python3 astrym.py sub example.com --stealth
python3 astrym.py domain github.com --aggressive
```

---

Флаги

Флаг Что делает
-x, --extras Extended sources (100+ OSINT)
-f <fmt> console, json, html, csv, pdf, md, stix, topology, all
-w N Воркеры для sub
-W file Свой wordlist
--stealth Вежливый режим
--aggressive Быстрый режим
--since N Для timeline: за N дней
--port N Для ssl
--pages N, --depth N Для darkweb

---

Источники данных (free, без ключей)

DNS / WHOIS: системный resolver + fallback 8.8.8.8 / 1.1.1.1 / 9.9.9.9, ARIN / RIPE / APNIC / LACNIC / AFRINIC, RDAP (rdap.org)

GeoIP: ip-api.com, ipwho.is, ipapi.co, ipinfo.io

ASN: RIPE Stat (as-overview, announced-prefixes, asn-neighbours, network-info)

CT-логи: crt.sh, Certspotter

Passive DNS: HackerTarget, AnubisDB, RapidDNS, BufferOver, CIRCL.lu, OTX

Threat intel: URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan InternetDB, OTX, Feodo, IPsum, Blocklist.de, Spamhaus DROP

Email: MX, SMTP, Gravatar, XposedOrNot, Disify, EmailRep, MTA-STS, PGP

Прочее: Ahmia, Wayback Machine

Диск-кэш RIPE Stat: ~/.astrym/cache/ripe/, TTL 1 час

---

Философия

Что делает

· Данные из публичных источников
· DNS, WHOIS, Certificate Transparency, публичные API
· Пассивный сбор — без прямого сканирования

Что НЕ делает

· ❌ Не сканирует порты
· ❌ Не подбирает пароли
· ❌ Не эксплуатирует уязвимости
· ❌ Не хранит персональные данные
· ❌ Не обходит аутентификацию

Ответственность

Использование ASTRYM против людей/организаций без согласия может нарушать GDPR, 152-ФЗ, CCPA, CFAA. Для пентеста — только с письменным разрешением.

---

Зависимости

Обязательные:

```
dnspython>=2.0
requests>=2.25
rich>=13.0
networkx>=2.8
```

Опциональные:

```
reportlab      # PDF-экспорт
phonenumbers   # команда phone
pycountry      # нормализация стран в consensus
geoip2         # локальная база MaxMind
```

---

Структура

```
astrym.py              точка входа
astrym_core.py         утилиты, конфиг, DNS, WHOIS, PROFILE
astrym_render.py       console-рендеры
astrym_output.py       export json/html/csv/pdf/md/topology
astrym_ip.py           ip + extended + consensus
astrym_domain.py       domain, dns, sub
astrym_email.py        email + SMTP + HIBP
astrym_check.py        threat intel + risk scoring
astrym_advanced.py     web, takeover, leak, origin, whois-history, darkweb
astrym_extra.py        ssl, phone, scan, watch, batch
astrym_asn.py          asn, cname (RIPE Stat + кэш)
astrym_web.py          permutation, http_probe, favicon, analytics
astrym_free.py         XposedOrNot, ThreatCrowd, ThreatMiner, Wayback
astrym_ahmia.py        поиск .onion
astrym_monitor.py      циклический watch + алерты
astrym_temporal.py     timeline
astrym_consensus.py    multi-source voting + anycast
astrym_graph.py        SQLite-граф
astrym_community.py    Louvain + GEXF
astrym_correlate.py    cross-target корреляция
astrym_topology.py     HTML vis.js граф
astrym_stix.py         STIX 2.1 writer
astrym_stix_output.py  STIX во все форматы
astrym_serve.py        REST API сервер
```

---

Лицензия

MIT — см. LICENSE

---

Сделано с уважением к сообществу OSINT.
