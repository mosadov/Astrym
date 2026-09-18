# ASTRYM

Open Source OSINT utility — 20+ команд, 50+ источников, REST API, граф инфраструктуры, consensus engine. Работает на Android (Termux), Linux, macOS, Windows. Не требует платных API для базового функционала.

## Содержание

Введение. Установка. Быстрый старт. Как читать вывод. Команды. Комбинирование фич. Форматы вывода. REST API. Граф и аналитика. Интеграции. Флаги и профили. Источники данных. Структура проекта. Что НЕ делает ASTRYM. Лицензия.

## Введение

ASTRYM — один Python-скрипт с модулями. Точка входа astrym.py, остальные astrym_*.py подключаются автоматически. Идея: даёшь цель (IP, домен, email, телефон, ASN), он собирает всё что есть в открытых источниках, голосует мнения разных источников через consensus-движок, кладёт результат в граф, отдаёт в 8 форматах — от консоли до PDF и STIX.

Ключевые термины. Target — что анализируешь: github.com, 8.8.8.8, test@gmail.com, AS15169. Kind — тип цели: ip, domain, email, asn, phone, url. Command — что делать: ip, domain, check, sub, ssl. Format — куда выводить: console, json, html, md, csv, pdf, stix, topology. Profile — насколько агрессивно: stealth, normal, aggressive. Consensus — голосование по источникам, насколько достоверны данные. Graph — SQLite-база всех сканов, где ищутся связи.

## Установка

Termux (Android). Выполни по одной строке:

pkg update && pkg upgrade

pkg install python dnsutils curl

pip install dnspython requests rich networkx reportlab phonenumbers pycountry

Linux. Выполни:

sudo apt install python3 python3-pip dnsutils

pip3 install -r requirements.txt

Проверка. Выполни: cd /storage/emulated/0/astrym1 && python3 astrym.py selfcheck

selfcheck покажет версию Python, установленные модули (dnspython, requests, rich, reportlab, phonenumbers), состояние DNS-резолвера, путь к графу, куда пишутся результаты.

## Быстрый старт

Три команды чтобы понять суть:

python3 astrym.py domain github.com

python3 astrym.py domain github.com -x -f all

python3 astrym.py

Что произойдёт. Программа соберёт DNS-записи, WHOIS, crt.sh поддомены, голосует consensus по registrar/NS. Результат положит в ~/.astrym/graph/astrym.db. Создаст файлы в results/domain/domain1.json, .html, .csv, .pdf, .md, _topology.html. Выведет цветной отчёт в консоль.

Флаги для быстрых вариаций. -x — Extended sources (100+ OSINT вместо 20 базовых). -f all — Сохранить во все форматы. --stealth — Вежливо, медленно, длинные таймауты. --aggressive — Быстро, 150 воркеров, короткие таймауты.

## Как читать вывод

Пример domain github.com. Первая строка — ASTRYM | Domain Analysis — название команды. Вторая — github.com — цель.

Блок DNS Records. A — IPv4-адрес. MX — почтовый сервер, цифра перед ним приоритет (меньше = важнее). NS — nameserver, кто отвечает за DNS-зону.

Блок Subdomains CT. Поддомены из Certificate Transparency logs (crt.sh), пассивный источник. [+] — зелёная галочка. Found N — количество найденных.

Блок WHOIS. registrar — компания-регистратор. creation date — когда зарегистрирован. name server — DNS-сервер в WHOIS. dnssec — подписан ли криптографически.

Блок Consensus (multi-source). Уровни уверенности: confirmed — ≥3 источника и ≥60% согласия. likely — ≥2 источника и ≥50% согласия. single — только 1 источник. weak — согласие <50%. conflict — нет большинства. anycast — специальный случай для public-DNS IP. Цифры (2/2) — сколько источников сказали это значение из общего числа. Альтернативы показываются снизу со стрелкой.

Блок DNS errors. Если резолвер не смог что-то спросить — ошибка здесь. Обычно не появляется (есть fallback на 8.8.8.8).

Блок Extended sources. -x включает дополнительные источники.

Блок External services. Ссылки на веб-интерфейсы внешних сервисов.

## Команды

### ip <addr> — анализ IP-адреса

python3 astrym.py ip 8.8.8.8

Что делает: WHOIS + GeoIP (4 источника) + reverse DNS + 11 DNSBL (списки спама) + ASN + consensus.

Ключевые строки вывода. PTR — обратное DNS. Country / City / ISP / ASN — геолокация и принадлежность. DNSBL — 11 чёрных списков, clean = не в списке, listed = в списке. Consensus — итог по всем источникам. Extended sources — что увидит, если добавить -x.

Флаги: python3 astrym.py ip 8.8.8.8 -x   ·   python3 astrym.py ip 8.8.8.8 -x -f all   ·   python3 astrym.py ip 8.8.8.8 -x --aggressive

### domain <domain> — анализ домена

python3 astrym.py domain github.com

Что делает: все DNS-типы + WHOIS + RDAP + crt.sh + consensus.

Ключевые строки. DNS Records — A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV. Subdomains CT — через crt.sh. WHOIS — из ARIN/RIPE/APNIC. Consensus — голосование по registrar, датам, NS, dnssec.

### dns <domain> — только DNS

python3 astrym.py dns example.com

Что делает: тот же resolve_all, но без WHOIS и поддоменов. Быстро. Ключевые строки: каждая секция — один тип записи. DNSSEC — enabled или not enabled.

С флагом: python3 astrym.py dns example.com -x

### sub <domain> — поддомены

python3 astrym.py sub example.com

Что делает: crt.sh + brute-force (~1000 слов) + 7 пассивных источников + permutation + HTTP probe.

Ключевые строки. Stats: CT — сколько нашли через crt.sh, Brute — сколько через перебор, Unique — итого уникальных. Results — таблица: хост [источники] [HTTP код].

Флаги: -w 100 (больше воркеров)   ·   -W words.txt (свой wordlist)   ·   --no-probe   ·   --no-permute   ·   --stealth

### email <addr> — email OSINT

python3 astrym.py email test@gmail.com

Что делает: MX + SMTP-проверка ящика + Gravatar + HIBP + XposedOrNot + PGP + MTA-STS.

Ключевые строки. Overview — провайдер, disposable. MX — почтовые серверы домена. SMTP — статус ящика: valid (250), invalid (550), greylisted (450), timeout/port_blocked (порт 25 закрыт). Gravatar — есть ли аватар. HIBP — утечки, BREACHED (N) + список. Утечки (XposedOrNot) — бесплатная альтернатива HIBP без ключа.

### check <target> — threat intel

python3 astrym.py check 8.8.8.8

Что делает: VirusTotal + AbuseIPDB + GreyNoise + Shodan + URLhaus + ThreatFox + OTX + Feodo + IPsum + Blocklist.de + Spamhaus DROP → risk score 0..100.

Ключевые строки. Risk: Score — 0 (чисто) до 100 (критично), Level — CLEAN/LOW/MEDIUM/HIGH/CRITICAL, Reasons — за что начислены баллы. VIRUSTOTAL — malicious/suspicious/harmless. GREYNOISE — malicious/benign/unknown. URLHAUS, THREATFOX — есть ли в базах malware. SHODAN_INTERNETDB — открытые порты + CVE.

Пример чистого IP:

Risk
  Score    0/100
  Level    CLEAN

Пример грязного:

Risk
  Score    55/100
  Level    HIGH
  · VirusTotal: 3 malicious (+19)
  · URLhaus: malware_download (5 urls, +25)

С флагом: python3 astrym.py check 8.8.8.8 -x

### ssl <domain> — сертификат

python3 astrym.py ssl github.com

Что делает: TLS handshake, читает сертификат, проверяет устаревшие протоколы (TLS 1.0/1.1), HSTS.

Ключевые строки. Protocol — TLS 1.3 / TLS 1.2 (TLS 1.0/1.1 плохо). Cipher — алгоритм шифрования. Subject CN — на кого выдан. Issuer CN — кто выдал. Days valid — сколько осталось. SAN — все домены на сертификате (часто даёт новые поддомены).

### scan <target> — автоопределение

python3 astrym.py scan github.com

Что делает: определяет тип цели (ip/domain/email) и запускает полный прогон + threat intel.

Ключевые строки. detected: domain — что определил. Дальше весь вывод domain + блок Risk из check.

### web <domain> — fingerprint

python3 astrym.py web example.com

Что делает: запрашивает сайт, читает headers, ищет CMS, проверяет 12 типовых путей (.env, .git/config, /wp-admin/), детектирует wildcard 200.

Ключевые строки. Final URL — куда редиректнуло. Status — HTTP-код. Technologies — WordPress, Nginx, Cloudflare. Headers — Server, X-Powered-By. Exposed paths: [err] 200 — уязвимо, [warn] 401/403 — защищено. Filtered false positives — сколько путей отсеяли. Favicon Hash — MurmurHash3 от favicon. Shared Analytics IDs — Google Analytics / Yandex Metrica ID.

### origin <domain> — настоящий IP за Cloudflare

python3 astrym.py origin example.com

Что делает: ищет IP за Cloudflare через SPF-записи, общие поддомены (direct, origin, mail, ftp).

Ключевые строки. Cloudflare — yes/no. Current — текущие IP. Candidate origin IPs — потенциальные настоящие IP. Sources — откуда взяли: txt_spf, subdomains, hackertarget.

### takeover <domain> — subdomain takeover

python3 astrym.py takeover example.com

Что делает: берёт поддомены из crt.sh, проверяет CNAME на 20 известных сервисов (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel), ищет сигнатуры «не настроен».

Ключевые строки. Checked — сколько проверили. Vulnerable — сколько уязвимы. [err] sub.example.com -> GitHub Pages — конкретный поддомен + сервис.

### leak <domain> — утечки

python3 astrym.py leak example.com

Что делает: GitHub Code Search + paste dorks (15 сайтов × 15 паттернов).

Ключевые строки. GitHub — репозитории и файлы. Paste sites dorks — сгенерированные запросы для ручного поиска.

### whois-history <domain> — timeline WHOIS

python3 astrym.py whois-history example.com

Что делает: timeline через crt.sh + RDAP + whoisxmlapi.

Ключевые строки. Timeline — даты и события. Sources used — какие источники ответили.

### darkweb <.onion> — Tor crawl

python3 astrym.py darkweb http://xxx.onion

Что делает: заходит через SOCKS5 Tor (127.0.0.1:9050), собирает email, телефоны, BTC-адреса, другие onion. Требует запущенный Tor.

Ключевые строки. Pages — сколько страниц обошли. EMAILS, PHONES, BITCOIN, ONIONS — извлечённые сущности.

С флагами: python3 astrym.py darkweb http://xxx.onion --pages 10 --depth 2

### phone <+num> — телефон

python3 astrym.py phone +79001234567

Что делает: парсит номер, определяет оператора/регион/тип линии, генерирует ссылки в мессенджеры и Google Dorks.

Ключевые строки. E.164 — стандартный формат. Country — ISO-код страны. Carrier — оператор. Line type — mobile/fixed/voip. Messengers — WhatsApp/Telegram/Viber. Reputation — Truecaller/Getcontact/Sync.me. Google Dorks — 9 запросов.

### asn <AS15169> — информация об ASN

python3 astrym.py asn AS15169

Что делает: RIPE Stat — имя/страна ASN, список анонсируемых префиксов, peers (upstream/downstream).

Ключевые строки. ASN Info — номер, имя, страна. Announced Prefixes (N) — все сети. Upstream ASNs — через кого анонсится. Downstream ASNs — кто через него анонсится.

Кэш: первый запрос идёт в сеть, второй в течение часа — мгновенно из ~/.astrym/cache/ripe/.

### cname <domain> — цепочка CNAME

python3 astrym.py cname example.com

Что делает: трассирует цепочку CNAME от домена до финального хоста/IP.

Ключевые строки. Chain (N hops) — шаги. Final — финальный хост + IP.

### ahmia <query> — поиск .onion

python3 astrym.py ahmia "market"

Что делает: поиск по Ahmia.fi (публичный индекс .onion) через clearweb, без Tor.

Ключевые строки. query — что искал. total — сколько найдено. #1, #2 — результаты с onion-адресом и описанием.

С флагом: python3 astrym.py ahmia --banned

### related <target> [depth] — что связано

python3 astrym.py related github.com 2

Что делает: BFS-обход графа. Показывает все узлы, достижимые от target за N шагов.

Ключевые строки. depth 0 — сама цель. depth 1 — прямые соседи (NS, MX, IP). depth 2 — соседи соседей.

### correlate <t1> <t2> ... — общее между целями

python3 astrym.py correlate github.com gitlab.com bitbucket.org

Что делает: ищет общие узлы (NS, ASN, registrar, cert_issuer) между целями.

Ключевые строки. Shared by ALL (N) — общие для всех. Shared by SOME (N) — общие для 2+.

### community [resolution] — Louvain

python3 astrym.py community

Что делает: автоматически находит скопления (сообщества) в графе.

Ключевые строки. modularity — качество разбиения (0..1). Выше 0.3 — хорошо. #1 size=42 — сообщество №1, размер 42 узла. kinds: subdomain:28, ip:8 — состав. targets: github.com — какие цели. top hubs — самые связанные узлы.

С параметром: python3 astrym.py community 1.5   ·   python3 astrym.py community 0.7

### gexf <out.gexf> — экспорт в Gephi

python3 astrym.py gexf /sdcard/graph.gexf

Что делает: сохраняет граф в GEXF (формат Gephi / Cytoscape). Узлы подкрашены по Louvain-сообществам.

Открыть: Gephi → File → Open → graph.gexf. Для цвета: Appearance → Nodes → Partition → community → Apply.

### timeline <target> — изменения во времени

python3 astrym.py timeline github.com

Что делает: читает снапшоты из SQLite (~/.astrym/graph/astrym.db), показывает diff между последовательными сканами. Требует ≥2 скана одной цели.

Ключевые строки. scans — сколько сканов. first/last — даты. events — сколько изменений. [дата] scan#N — конкретное событие: +3 (добавлено 3 узла), -1 (удалён 1), ~0 (изменено 0).

С флагом: python3 astrym.py timeline github.com --since 7

### consensus <ip> — только голосование

python3 astrym.py consensus 8.8.8.8

Что делает: собирает данные из всех источников, голосует. Не показывает остальные данные IP.

Ключевые строки. confirmed/likely/single/weak/conflict — сколько полей в каждой категории. Consensus (multi-source) — таблица.

### watch <target> — снапшот + diff

python3 astrym.py watch github.com

Что делает: сохраняет снапшот в ~/.astrym/watches/. При следующем запуске показывает diff.

Ключевые строки. Первый запуск: [+] first snapshot saved. Второй: [+] added, [-] removed, [~] changed.

### monitor <target> — циклический watch

python3 astrym.py monitor github.com --interval 3600 --cycles 24 --quiet &

Что делает: каждые N секунд сканирует цель, при изменениях пишет в лог.

Ключевые строки. interval: 3600s, cycles: 24 — параметры. alerts log: ~/.astrym/alerts/github.com.log — где лог. --- cycle N --- — номер цикла. no changes / CHANGES: +3 -1.

Смотреть в реальном времени: tail -f ~/.astrym/alerts/github.com.log

### batch <file> — список целей

python3 astrym.py batch targets.txt

Файл targets.txt содержит строки вида: domain github.com, ip 8.8.8.8, email test@gmail.com, check 1.1.1.1, sub example.com. Каждая строка — отдельная команда + цель. Выполнятся по очереди.

### push <target> — экспорт в /sdcard

python3 astrym.py push github.com

Что делает: скан + markdown в /sdcard/astrym-drop/ с timestamp в имени. Удобно для импорта в AFFiNE через File Manager.

Ключевые строки. pushed: /sdcard/astrym-drop/github.com_2026-09-18T12-30-15.md. AFFiNE: File → Import → Markdown.

### stix <target> — STIX 2.1 bundle

python3 astrym.py stix github.com

python3 astrym.py stix github.com -f all

Что делает: собирает скан и упаковывает в STIX 2.1 bundle.json — стандарт обмена threat intel.

Ключевые строки. Bundle: ID (UUID), Spec (2.1), Objects (сколько объектов), File (путь). Objects by type — domain-name: 10, relationship: 11. Import — куда импортировать: MISP, OpenCTI, TheHive.

Файл: results/stix/<target>_bundle.json.

## Комбинирование фич

Сценарий 1: разведка одного домена.

python3 astrym.py domain github.com -x -f all

python3 astrym.py ssl github.com -f md

python3 astrym.py web github.com

python3 astrym.py sub github.com --aggressive

python3 astrym.py takeover github.com

После этого в графе есть ВСЁ про github.com. Дальше: python3 astrym.py related github.com 2   ·   python3 astrym.py timeline github.com

Сценарий 2: сравнить несколько целей.

python3 astrym.py domain github.com

python3 astrym.py domain gitlab.com

python3 astrym.py domain bitbucket.org

python3 astrym.py correlate github.com gitlab.com bitbucket.org

python3 astrym.py community

Сценарий 3: отслеживать изменения.

python3 astrym.py watch example.com

python3 astrym.py monitor example.com --interval 86400 --cycles 30 --quiet &

tail -f ~/.astrym/alerts/example.com.log

Сценарий 4: экспорт в AFFiNE.

python3 astrym.py push github.com

Файл в /sdcard/astrym-drop/. В AFFiNE: File → Import → Markdown → выбираешь файл.

Сценарий 5: STIX для SOC.

python3 astrym.py check 8.8.8.8 -x

python3 astrym.py stix 8.8.8.8 -f all

Файл results/stix/8.8.8.8_bundle.json → в MISP / OpenCTI.

Сценарий 6: REST API.

Терминал 1: bash ~/astrym-go.sh

Терминал 2 или браузер: curl -H "X-API-Key: $KEY" 'http://127.0.0.1:8080/scan/domain/github.com?format=html'

Сценарий 7: batch.

Создай targets.txt со строками: domain github.com, ip 8.8.8.8, check 1.1.1.1. Запусти: python3 astrym.py batch targets.txt

## Форматы вывода

console — Цветной вывод, никуда не сохраняется. json — Машиночитаемый JSON в results/<kind>/<kind>N.json. html — Тёмный отчёт в results/<kind>/<kind>N.html. csv — Для Excel в results/<kind>/<kind>N.csv. pdf — PDF с кириллицей в results/<kind>/<kind>N.pdf. md — Markdown + frontmatter в results/<kind>/<kind>N.md. topology — HTML-граф vis.js в results/<kind>/<kind>N_topology.html. stix — STIX 2.1 bundle в results/stix/<target>_bundle.json. all — Все сразу.

Пример: python3 astrym.py domain github.com -f all — создаст 6 файлов (.json, .html, .csv, .pdf, .md, _topology.html).

Использование. json — для скриптов и пайплайнов. html — для просмотра в браузере. csv — для Excel / pandas. pdf — для отправки клиенту. md — для AFFiNE / Obsidian / Logseq. topology — для интерактивной карты в браузере.

## REST API

Сервер на голом http.server, ноль зависимостей.

Запуск. python3 astrym_serve.py --genkey (один раз, сгенерировать ключ). python3 astrym_serve.py (запустить на 127.0.0.1:8080). python3 astrym_serve.py --host 0.0.0.0 (для доступа из браузера).

Хелпер-скрипт одной командой: bash ~/astrym-go.sh. Она сама выключит ключи, убьёт старый сервер, поднимет новый, покажет URL.

Эндпоинты. GET /health — статус (без ключа). GET /info — версия, граф, RIPE-кэш. GET /kinds — список команд. GET /scan/<kind>/<target>?format=json|md|html|stix — скан одной цели. POST /batch — несколько целей одним запросом.

Примеры.

KEY=$(python3 astrym_serve.py --list-keys | head -1)

curl http://127.0.0.1:8080/health

curl -H "X-API-Key: $KEY" http://127.0.0.1:8080/kinds

curl -H "X-API-Key: $KEY" http://127.0.0.1:8080/scan/domain/github.com

curl -H "X-API-Key: $KEY" 'http://127.0.0.1:8080/scan/ip/8.8.8.8?extras=1&format=md'

curl -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"lines":["domain github.com","ip 8.8.8.8"]}' http://127.0.0.1:8080/batch

Открыть в браузере. Android изолирует Termux от браузера: 127.0.0.1 в браузере — это НЕ тот 127.0.0.1, что в Termux. Решение — слушать 0.0.0.0 и обращаться по локальному IP: http://192.168.x.x:8080/scan/domain/github.com?format=html. Локальный IP: ifconfig | grep "inet ".

## Граф и аналитика

Всё что сканируется кладётся в ~/.astrym/graph/astrym.db (SQLite).

Что даёт. related — связи между целями. correlate — общие узлы между 2+ целями. community — автоматические скопления (Louvain). timeline — изменения во времени. gexf — экспорт в Gephi.

Узлы и рёбра. Nodes: domain, ip, subdomain, ns, mx, asn, registrar, cert_issuer, country, isp, email, port, leak_path, threat_hit. Edges: HAS_SUB, RESOLVES_TO, NS, MX, REGISTERED_BY, IN_ASN, CERT_ISSUED_BY, FLAGGED_BY.

Посмотреть статистику: python3 astrym.py graph stats   ·   python3 astrym.py graph targets

## Интеграции

AFFiNE. Формат md (с YAML-frontmatter) импортируется в AFFiNE: File → Import → Markdown → выбрать results/<kind>/<kind>N.md. Или через /sdcard/astrym-drop/ после push.

MISP / OpenCTI / TheHive. STIX 2.1 bundle (results/stix/<target>_bundle.json) импортируется штатными средствами. MISP: Administration → Feeds → Import → STIX 2.1. OpenCTI: Data → Import → STIX 2.1 bundle. TheHive: Templates → STIX → Upload. PyMISP: misp.upload_stix('/path/to/bundle.json').

REST API. Из любой программы на Python: requests.get("http://127.0.0.1:8080/scan/domain/github.com", headers={"X-API-Key": "ak_..."}).

Gephi / Cytoscape. GEXF-файл открывается напрямую.

Obsidian / Logseq / Typora. Формат md из -f md — обычный Markdown с frontmatter, всё работает без адаптеров.

## Флаги и профили

-x, --extras — Extended sources (100+ OSINT). -f <fmt> — Формат: console, json, html, csv, pdf, md, stix, topology, all. -w N — Воркеры для sub (default 40). -W file — Свой wordlist. -s, --security — Threat intel к ip/domain. --port N — Порт SSL (default 443). --pages N — Страниц для darkweb. --depth N — Глубина darkweb. --since N — Для timeline: за N дней. --stealth — Вежливый режим. --aggressive — Быстрый режим. --no-probe — Для sub: без HTTP probe. --no-permute — Для sub: без permutation.

Профили. stealth: пауза 3.0s, HTTP timeout 30s, DNS timeout 8s, воркеров 8, sub-воркеров 10. normal: пауза 0.4s, HTTP 10s, DNS 3s, воркеров 40, sub 40. aggressive: пауза 0.05s, HTTP 5s, DNS 2s, воркеров 150, sub 200.

Когда что. --stealth — против сайтов, которые могут забанить. Медленно, но безопасно. normal — по умолчанию. --aggressive — когда сканируешь свои цели или нужно быстро.

## Источники данных

Free без ключей. DNS/WHOIS: системный resolver + fallback 8.8.8.8 / 1.1.1.1 / 9.9.9.9, WHOIS ARIN/RIPE/APNIC/LACNIC/AFRINIC, RDAP (rdap.org), GeoIP ip-api.com ipwho.is ipapi.co ipinfo.io, ASN RIPE Stat, CT crt.sh и Certspotter, Passive DNS HackerTarget AnubisDB RapidDNS BufferOver CIRCL.lu OTX. Threat intel: URLhaus, ThreatFox, MalwareBazaar, GreyNoise, Shodan InternetDB, OTX, Feodo, IPsum, Blocklist.de, Spamhaus DROP. Email: MX, SMTP, Gravatar, XposedOrNot, Disify, EmailRep, MTA-STS, PGP. Прочее: Ahmia, Wayback Machine.

API опционально. Ключи в ~/.astrym/config.json: virustotal, abuseipdb, shodan, hibp, securitytrails, censys_id, censys_secret, hunter.

Диск-кэш RIPE Stat. Запросы к RIPE Stat кэшируются в ~/.astrym/cache/ripe/ с TTL 1 час. Второй запуск asn AS15169 — мгновенно. Посмотреть: python3 -c "from astrym_asn import cache_stats; print(cache_stats())". Очистить: python3 -c "from astrym_asn import cache_clear; print(cache_clear())". Отключить: ASTRYM_RIPE_TTL=0 python3 astrym.py asn AS15169.

## Структура проекта

astrym.py — главный файл (точка входа, dispatch, menu). astrym_core.py — утилиты, конфиг, DNS, WHOIS, PROFILE. astrym_render.py — console-рендеры. astrym_output.py — export json/html/csv/pdf/md/topology. astrym_ip.py — ip + extended + consensus. astrym_domain.py — domain, dns, sub. astrym_email.py — email + SMTP + HIBP. astrym_check.py — threat intel + risk scoring. astrym_advanced.py — web, takeover, leak, origin, whois-history, darkweb. astrym_extra.py — ssl, phone, scan, watch, batch. astrym_asn.py — asn, cname (RIPE Stat + диск-кэш). astrym_web.py — permutation, http_probe, favicon, analytics. astrym_free.py — XposedOrNot, ThreatCrowd, ThreatMiner, Wayback. astrym_ahmia.py — поиск .onion. astrym_monitor.py — циклический watch + алерты. astrym_temporal.py — timeline из SQLite snapshots. astrym_consensus.py — multi-source field voting. astrym_graph.py — SQLite-граф инфраструктуры. astrym_community.py — Louvain + GEXF. astrym_correlate.py — cross-target корреляция. astrym_topology.py — HTML vis.js граф. astrym_stix.py — STIX 2.1 bundle writer. astrym_stix_output.py — STIX во все форматы. astrym_serve.py — REST API сервер. astrym_test.py — self-test.

## Что НЕ делает ASTRYM

Не сканирует порты — только читает чужие базы (Shodan InternetDB). Не подбирает пароли. Не эксплуатирует уязвимости — только ищет открытые двери, не входит. Не хранит персональные данные — только результаты сканов. Не обходит аутентификацию.

Ответственность. Использование ASTRYM против людей/организаций без согласия может нарушать GDPR, 152-ФЗ, CCPA, CFAA. Для пентеста — только с письменным разрешением.

## Лицензия

MIT License. Свободно для использования, модификации и распространения.

Сделано с уважением к сообществу OSINT.