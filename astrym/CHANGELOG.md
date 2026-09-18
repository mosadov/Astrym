# ASTRYM CHANGELOG

Обратный хронологический порядок (свежее сверху). Все изменения проекта ASTRYM.

## 2026-09-18 — REST API (этапы 1-2)

Добавлено. astrym_serve.py (v2.0.0) — REST API на голом http.server, ноль зависимостей. Эндпоинты: GET /health (статус без ключа), GET /info (версия, граф, RIPE-кэш), GET /kinds (список команд), GET /scan/<kind>/<target>?format=json|md|html|stix (скан одной цели), POST /batch (до 20 целей одним запросом). API-ключи через --genkey / --list-keys / --revoke-key. Авторизация по X-API-Key заголовку или ?key= в URL. Режим без ключей (DEV MODE) для локального использования. CORS-заголовки для браузера. Response headers: X-ASTR YM-Duration, X-ASTR YM-Kind, X-ASTR YM-Format.

Вспомогательные скрипты. ~/astrym-go.sh — запуск одной командой: выключает ключи, убивает старый процесс, поднимает новый сервер на 0.0.0.0:8080, печатает локальный URL для браузера.

Android-нюанс. Termux и браузер в разных network namespace. 127.0.0.1 из браузера не работает. Решение: слушать 0.0.0.0, обращаться через 192.168.x.x (локальный IP телефона).

Патчи. patch_serve1.py — этап 1 (MVP). patch_serve2.py — этап 2 (форматы + batch + kinds/info).

Этапы 3-6 отложены. /graph/* — stats, targets, related, correlate, community, gexf. /timeline/*, /stix/* — экспорт файлов. /monitor + вебхуки (Discord/Telegram). astrym.py serve --daemon.

## 2026-09-18 — STIX 2.1 во все форматы

Добавлено. astrym_stix_output.py (v9.9.1) — рендер STIX во все форматы. save_stix_json — bundle как есть. save_stix_html — тёмный отчёт с badge'ами по типам объектов. save_stix_csv — плоская таблица (objects + relationships). save_stix_pdf — PDF с кириллицей. save_stix_md — Markdown с frontmatter для AFFiNE. save_stix_topology — vis.js граф STIX-объектов. output_stix_results — единая точка входа.

Изменено. astrym_output.py: override output_results — для auto_kind == "stix" делегирует в astrym_stix_output. astrym.py: run_once теперь также пишет файлы когда -f all для спец-команд (asn, cname, timeline, consensus, stix).

Использование. python3 astrym.py stix github.com -f all — генерирует все форматы STIX сразу.

Патчи. patch_stix_fmt.py (создание модуля + патч output). patch_stix_fmt2.py (фикс run_once — сначала не нашёл якорь, потом через универсальный поиск блока).

## 2026-09-18 — STIX 2.1 export (базовый)

Добавлено. astrym_stix.py (v9.9.0) — свой writer, без библиотеки stix2. Функции: build_bundle(result) — STIX 2.1 bundle dict. export_stix(result, out_path) — запись в файл. run_stix(target, extras) — скан + bundle. render_stix(d) — console-рендер.

Маппинг kinds → STIX. domain → domain-name. ip → ipv4-addr / ipv6-addr. asn → autonomous-system. email → email-addr. risk ≥ 15 → indicator (с confidence=score). threat hits → indicator + relationship indicates. subdomains → domain-name + relationship related-to. producer → identity (ASTRYM). все observable → observed-data (с timestamp).

Файл. results/stix/<target>_bundle.json.

Импорт. MISP: Administration → Feeds → Import (STIX 2.1). OpenCTI: Data → Import → STIX 2.1 bundle. TheHive: Templates → STIX → Upload. PyMISP: misp.upload_stix('/path/bundle.json').

Патч. patch_stix.py.

## 2026-09-18 — Consensus для domain + confidence в форматах

Добавлено. astrym_consensus.py: domain-часть. consensus_for_domain(result) — голосование по registrar/creation_date/name_server/dnssec. aggregate_domain(result) — обёртка. render_consensus_domain(result) — standalone рендер. _fetch_rdap_domain(domain) — RDAP через rdap.org. _norm_registrar, _norm_date, _norm_ns, _norm_dnssec. _md_badge, _html_badge — для новых форматов вывода.

Confidence-бейджи в Markdown и HTML. Таблица Consensus в _md_domain и _html_domain с полями Field | Value | Confidence.

Изменено. astrym_domain.py: d["consensus"] в run_domain. astrym_render.py: блок consensus в render_domain. astrym_output.py: таблица Consensus в _md_domain и _html_domain. astrym_core.py: KNOWN_CMDS += domain-consensus.

Патч. patch_consensus_domain.py.

## 2026-09-18 — Consensus engine (базовый, IP)

Добавлено. astrym_consensus.py (v9.9.0). FieldConsensus — класс для голосования по одному полю. collect_consensus(sources_dict, field_map) — сбор мнений. consensus_for_ip(ip_result) — обёртка для IP. aggregate(ip_result) — + anycast-флаг. render_consensus_block(), render_consensus(). run_consensus(target) — standalone команда. Нормализаторы: _norm_country, _norm_isp, _norm_asn, _norm_city, _norm_tz. Уровни: confirmed (≥3 и ≥60%), likely (≥2 и ≥50%), single, weak, conflict. Anycast-detection: _ANYCAST_V4 список public-DNS подсетей, is_anycast(ip). Multi-source: ip-api + ipwho + ipapi + ipinfo + bgpview + team_cymru.

Изменено. astrym_ip.py: d["consensus"] = aggregate(d) в run_ip. astrym_render.py: блок consensus в render_ip. astrym_core.py: KNOWN_CMDS += consensus. astrym.py: dispatch + menu.

Использование. python3 astrym.py consensus 8.8.8.8. python3 astrym.py ip 8.8.8.8 -x (consensus встроен в render).

Патчи. patch_consensus.py. patch_v2.py (неудачная попытка). patch_v3.py (splice_isp съел _norm_country, пришлось откатывать из .bak). patch_v4.py (успешно — append-only overrides без re.sub/splice). patch_fix_two_bugs.py (универсальный render_consensus_block + DNS fallback для resolve_detailed). patch_fix_ip_consensus_and_dnssec.py (render_ip anchor + dnssec misparse исправлен).

Known issue (исправлено). Ложный конфликт org: dns google public vs google — исправлено нормализатором. Ложный conflict city/region для anycast-IP — исправлено anycast-детектором. dnssec yes при unsigned — исправлено порядком проверок ("unsigned" in s до "signed" in s).

## 2026-09-18 — Markdown export (AFFiNE-compatible)

Добавлено. astrym_output.py::save_md(results, base). YAML-frontmatter (title/date/tool/type/target/tags). GFM-разметка: таблицы, списки, code-блоки. Per-type рендеры для 13 типов. _md_extended() — extended sources + external_links. _md_raw_block() — raw JSON в code-блоке (truncated 20k).

Изменено. -f all теперь включает md. Справка CLI и меню обновлены упоминанием md.

Патч. patch_md_export.py.

## 2026-09-18 — Волна 5 (temporal only)

Добавлено. astrym_temporal.py (v9.8.0). build_timeline(target, since_days=None) — diff между последовательными сканами. run_temporal(), render_timeline(). Фикс мерцания: added только если никогда раньше, removed только если нигде после. Отсекает ложные diff'ы между сканами разных команд (domain → cname → domain).

Изменено. astrym.py: DISPATCH += timeline. astrym_core.py: KNOWN_CMDS += timeline, --since N.

Отменено. AI-анализ скана — не нужен по решению пользователя.

Патчи. patch_wave5_temporal.py (базовый). patch_tl.py (фикс мерцания — diff по пересечению, узел added только если его не было ни в одном предыдущем скане, removed только если не появится ни в одном следующем).

## 2026-09-18 — Волна 4: Ahmia + Monitor + Profiles

Добавлено. astrym_ahmia.py (v9.7.0) — поиск .onion через Ahmia (clearweb, без Tor). ahmia_search(query), ahmia_banned(). run_ahmia(), render_ahmia().

astrym_monitor.py (v9.7.0) — циклический watch + алерты. run_monitor(target, interval, cycles, quiet). run_monitor_cli(line) — разбор строки CLI. Логи алертов: ~/.astrym/alerts/<target>.log. _summarize_diff() — краткая сводка added/removed/changed.

Профили в astrym_core.py. PROFILE — текущий профиль. _PROFILES — stealth/normal/aggressive. set_profile(name) / get_profile().

Изменено. _rl_sleep() читает PROFILE['rl_sleep']. Флаги --stealth/--slow/--quiet-net и --aggressive/--fast/--max в parse_cli_line. workers автоматически меняется по профилю (8/40/150). astrym.py DISPATCH += ahmia. astrym.py main() + interactive_loop — обработка monitor. Меню: строки ahmia и monitor. astrym_core.py KNOWN_CMDS += ahmia.

Профили интенсивности. stealth: rl_sleep 3.0s, http_timeout 30s, dns_timeout 8s, workers 8, sub_workers 10, probe_workers 5. normal: 0.4s, 10s, 3s, 40, 40, 20. aggressive: 0.05s, 5s, 2s, 150, 200, 60.

Патчи. patch_wave4_ahmia.py. patch_wave4_monitor.py. patch_wave4_profiles.py.

## 2026-09-18 — Волна 3: Louvain + GEXF

Добавлено. astrym_community.py (v9.6.0). load_networkx_graph() — читает SQLite-граф в networkx.Graph. louvain_communities() — встроено в networkx >= 2.8 (python-louvain не нужен). detect_communities(resolution, min_size, exclude_kinds). export_gexf(path, color_by_community, resolution) — GEXF 1.2. summarize_community() — топ-хабы по degree, kinds, targets. _community_palette() — HSV-палитра на N сообществ.

Изменено. astrym.py: _cmd_community(args), _cmd_gexf(args). astrym.py меню — строки community и gexf. astrym_core.py KNOWN_CMDS += community, gexf. astrym_core.py::parse_cli_line — разрешены команды без targets (NO_TARGET_OK = {community, graph, related, correlate, gexf}).

Зависимости. networkx >= 2.8 (установлено 3.6.1).

Патчи. patch_add_community.py (интеграция модуля). patch_community_harden.py (traceback при ошибках). patch_fix_parse_cli.py (команды без targets). patch_fix_gexf.py (viz.color как dict {r,g,b,a}, не hex-строка — иначе "'str' object has no attribute 'get'" в networkx GEXF-writer).

Fixed. Ошибка 'str' object has no attribute 'get' в GEXF-writer. networkx требует viz.color как dict {r,g,b,a} (int), а не hex-строку. Заменено: _hex_to_rgba() + запись в int-RGBA.

## 2026-09-18 — Диск-кэш RIPE Stat

Добавлено. astrym_asn.py: override _ripe_get с дисковым кэшем. Кэш: ~/.astrym/cache/ripe/<sha1>.json. TTL: 3600 сек (1 час). Env override: ASTRYM_RIPE_TTL=N (0 = отключить). Функции cache_stats() и cache_clear(). Кэш работает для всех запросов к RIPE Stat: as-overview, announced-prefixes, asn-neighbours, network-info.

Ускорение. Второй запуск asn AS15169 в течение часа — мгновенно (миллисекунды вместо секунд). Все команды, использующие RIPE, ускоряются в 10-20 раз на повторных запусках.

Патчи. patch_cache.py (override _ripe_get, append-only). patch_asn_render.py (fix render_asn под строки RIPE Stat, поддержка обоих форматов: list[str] и list[dict]).

## 2026-09-18 — BGPView → RIPE Stat (полностью закрыто)

Причина. Домен api.bgpview.io перестал разрешаться (NXDOMAIN). Сервис BGPView официально закрыт 26.11.2025.

Патч 1. patch_astrym_asn.py. asn_info_bgpview → RIPE Stat as-overview/data.json. asn_prefixes_bgpview → RIPE Stat announced-prefixes/data.json. Добавлены алиасы asn_info / asn_prefixes. Сохранены сигнатуры (dict|None, list[str]).

Патч 2. patch_bgpview_cleanup.py. asn_peers_bgpview → RIPE Stat asn-neighbours/data.json. astrym_ip.py::_x_ip[bgpview] → RIPE Stat network-info + as-overview. Ключ bgpview в extended оставлен для совместимости с графом.

Проверено. grep -rn "bgpview.io" *.py — совпадения только в самих патчах. astrym.py asn AS15169 — RIPE Stat отдаёт data. astrym.py ip 8.8.8.8 -x — блок bgpview с source: ripe-stat.

## 2026-09-18 — Markdown export (AFFiNE-compatible)

Добавлено. astrym_output.py::save_md(results, base). YAML-frontmatter (title, date, tool, type, target, tags). GFM-разметка: таблицы, списки, code-блоки, заголовки. Per-type рендеры для 13 типов (ip, domain, dns, sub, email, check, ssl, web, takeover, origin, whois-history, phone, darkweb). Generic fallback для остальных. _md_extended() — extended sources + external links. _md_raw_block() — raw JSON в code-блоке, truncated 20k символов.

Изменено. Формат -f all теперь включает md. Справка CLI и меню обновлены: console,json,html,csv,pdf,md,all.

Использование. astrym.py domain github.com -f md. astrym.py ip 8.8.8.8 -f all. Импорт в AFFiNE через File → Import → Markdown.

Патч. patch_md_export.py (идемпотентный, делает .bak).

## 2026-09-18 — Волна 5 (temporal only)

Добавлено. astrym_temporal.py (v9.8.0). build_timeline(target, since_days=None) — diff между последовательными сканами цели из SQLite snapshots. run_temporal() / render_timeline(). Показывает added / removed / changed.

Изменено. astrym.py DISPATCH += timeline. astrym.py RENDER_ASN_EXTRA['timeline'] = render_timeline. astrym.py меню — новая строка. astrym_core.py KNOWN_CMDS += timeline. astrym_core.py parse_cli_line += --since N. astrym_core.py args dict += since_days.

Отменено. AI-анализ (LLM fingerprint) — исключён по решению пользователя. astrym_ai.py удаляется патчем если был установлен. Убраны: run_ai, render_ai, ai_provider, --provider.

Использование. astrym.py timeline github.com. astrym.py timeline github.com --since 7.

Патчи. patch_wave5_temporal.py.

Known issue. Diff реагирует на состав ключей в result, поэтому узлы типа cname-chain/web/leak_path могут мерцать между сканами разных команд на одной цели. Возможные стратегии: (A) diff только по пересечению ключей, (B) нормализация snapshot перед сравнением.

## 2026-09-18 — Волна 4: Ahmia + Monitor + Profiles

Добавлено. astrym_ahmia.py (v9.7.0) — ahmia_search(query), ahmia_banned(), run_ahmia(), render_ahmia(). astrym_monitor.py (v9.7.0) — run_monitor(target, interval, cycles, quiet), run_monitor_cli(line), логи в ~/.astrym/alerts/<target>.log, _summarize_diff(). Профили в astrym_core.py: PROFILE, _PROFILES, set_profile(), get_profile(). _rl_sleep() читает PROFILE['rl_sleep'].

Изменено. astrym_core.py::parse_cli_line: флаги --stealth, --slow, --quiet-net и --aggressive, --fast, --max. workers автоматически меняется по профилю (8/40/150). astrym.py DISPATCH += ahmia. astrym.py main() + interactive_loop — обработка monitor. astrym.py меню — строки ahmia и monitor. astrym_core.py KNOWN_CMDS += ahmia.

Профили интенсивности. stealth: rl_sleep 3.0s, http_timeout 30s, dns_timeout 8.0s, workers 8, sub_workers 10, probe_workers 5. normal: 0.4s, 10s, 3s, 40, 40, 20. aggressive: 0.05s, 5s, 2s, 150, 200, 60.

Патчи. patch_wave4_ahmia.py. patch_wave4_monitor.py. patch_wave4_profiles.py.

## 2026-09-18 — Волна 3: Louvain communities + GEXF export

Добавлено. astrym_community.py (v9.6.0). load_networkx_graph() — читает SQLite-граф в networkx.Graph. louvain_communities() — встроенный nx.algorithms.community.louvain_communities (networkx >= 2.8, без python-louvain). detect_communities(resolution, min_size, exclude_kinds). export_gexf(path, color_by_community, resolution) — GEXF 1.2. summarize_community() — топ-хабы по degree, kinds, targets. _community_palette() — HSV-палитра на N сообществ.

Изменено. astrym.py DISPATCH-обработка команд community и gexf. astrym.py _cmd_community(args) + _cmd_gexf(args). astrym.py меню — строки community и gexf. astrym_core.py KNOWN_CMDS += community, gexf. astrym_core.py::parse_cli_line — разрешены команды без targets (NO_TARGET_OK).

Использование. astrym.py community — Louvain-разбиение всего графа. astrym.py community 1.5 — мелкие сообщества. astrym.py community 0.7 — крупные скопления. astrym.py gexf <out.gexf> — экспорт для Gephi / Cytoscape / yEd.

Патчи. patch_add_community.py — интеграция модуля. patch_community_harden.py — traceback при ошибках. patch_fix_parse_cli.py — команды без targets. patch_fix_gexf.py — исправление формата viz.color.

Зависимости. networkx >= 2.8 (установлено 3.6.1).

Fixed. 'str' object has no attribute 'get' в GEXF-writer. networkx требует viz.color как dict {r,g,b,a} (int), а не hex-строку. Заменено: _hex_to_rgba() + запись в int-RGBA.

## 2026-09-18 — BGPView → RIPE Stat (полностью закрыто)

Причина. Домен api.bgpview.io перестал разрешаться (NXDOMAIN). Сервис BGPView официально закрыт 26.11.2025.

Патч 1 — patch_astrym_asn.py. asn_info_bgpview() → RIPE Stat as-overview/data.json. asn_prefixes_bgpview() → RIPE Stat announced-prefixes/data.json. Добавлены алиасы asn_info / asn_prefixes. Сохранены сигнатуры (dict|None, list[str]).

Патч 2 — patch_bgpview_cleanup.py. asn_peers_bgpview() → RIPE Stat asn-neighbours/data.json. astrym_ip.py::_x_ip[bgpview] → RIPE Stat network-info/data.json + as-overview/data.json. Ключ bgpview в extended оставлен для совместимости с графом.

Проверено. grep -rn "bgpview.io" *.py → совпадения только в самом патче. astrym.py asn AS15169 → RIPE Stat отдаёт data. astrym.py ip 8.8.8.8 -x → блок bgpview с source: ripe-stat.

## Предыдущее (до 2026-09-18, зафиксировано по README v9.5)

v9.5.0 — ASN discovery + CNAME chain. astrym_asn.py полностью. Команды asn, cname. ASN discovery через BGPView (позже мигрирован на RIPE Stat). trace_cname_chain() — полный путь CNAME.

v9.4.0 — permutation, HTTP probe, favicon, analytics. astrym_web.py. permute_subs() + resolve_permutations(). http_probe() — замена httpx. favicon_hash() — MurmurHash3 для Shodan-совместимости. extract_analytics() — shared tracking IDs.

v9.3.0 — бесплатные источники. astrym_free.py. XposedOrNot (замена HIBP), ThreatCrowd, ThreatMiner, Wayback CDX.

v9.1.5 — PDF Unicode + friendly empty strings. _register_unicode_font() — DejaVuSans / Roboto / Noto. Transliteration fallback для кириллицы. _ND, _ND_MX, _ND_A, ... — понятные сообщения вместо пустых полей.

v9.1.3 — wildcard 200 detection + расширенный wordlist. _probe_wildcard() + _is_wildcard_false_positive() в advanced. _validate_path_content() — проверка содержимого ответа. Wordlist расширен до ~1000+ слов с суффиксами. SMTP HELO fix (mailcheck.org вместо .local).

v9.1.2 — safe DNS resolver. _init_resolver() — fallback на 8.8.8.8 / 1.1.1.1 / 9.9.9.9. Работает в Termux/Docker/PyDroid без /etc/resolv.conf. dns_health() для self-check.

v9.0.0 — Graph Engine + correlate. astrym_graph.py — SQLite-граф инфраструктуры. astrym_correlate.py — cross-target корреляция. Таблицы: scans, nodes, edges, snapshots. ~/.astrym/graph/astrym.db.

v8.2.0 — topology (vis.js). astrym_topology.py. Интерактивный HTML-граф. Формат -f topology / -f all.

v8.1.0 — базовый ASTRYM. astrym.py, astrym_core.py, astrym_render.py, astrym_output.py. astrym_ip.py, astrym_domain.py, astrym_email.py. astrym_check.py (threat intel + risk scoring). astrym_advanced.py (web, takeover, leak, origin, whois-history, darkweb). astrym_extra.py (ssl, phone, scan, watch, batch). Форматы: console, json, html, csv, pdf.

## Отменённое

2026-09-18 — AFFiNE MCP-обёртка (auto-push страниц). Причина: AFFiNE 0.27.4 self-hosted без API-токена. Docker в Termux не даёт нужных namespaces без root. Node.js/npm не установлены. Решение: работаем через ручной импорт — File → Import → Markdown. Все форматы ASTRYM (md, html, json) остаются AFFiNE-совместимыми.

2026-09-18 — AI-fingerprint (Волна 5, вторая часть). Причина: не нужен по решению пользователя. Требовался бы внешний LLM endpoint (Groq / Gemini / OpenRouter / Ollama).

2026-09-18 — Disk-cache RIPE Stat (был в бэклоге, сделан в этой сессии). См. выше — patch_cache.py.

## Бэклог

REST API (этапы 3-6). /graph/* — stats, targets, related, correlate, community, gexf. /timeline/*, /stix/* — экспорт файлов. /monitor + вебхуки (Discord/Telegram). astrym.py serve --daemon (запуск из главного CLI).

Улучшения. Асинхронный POST /batch (сейчас синхронный, долгие цели держат соединение). Risk-scoring с confidence intervals. /graph эндпоинты для веб-дашборда.

Экспериментальное. Мульти-пользовательский режим. Интеграция с MISP (пуш/пул). Хранение сканов в S3-совместимом хранилище.