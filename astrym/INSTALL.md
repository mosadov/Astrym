# Установка ASTRYM

## Termux (Android)

    pkg update && pkg upgrade
    pkg install python dnsutils curl
    pip install dnspython requests rich networkx reportlab phonenumbers pycountry

## Linux / macOS

    sudo apt install python3 python3-pip dnsutils
    pip3 install -r requirements.txt

## Проверка

    cd astrym
    python3 astrym.py selfcheck
    python3 astrym.py domain github.com

## Опциональные зависимости

- reportlab     — PDF-экспорт (-f pdf)
- phonenumbers  — команда phone
- pycountry     — точная нормализация стран в consensus
- geoip2        — локальная база MaxMind

## API-ключи (опционально)

80% функционала работает без ключей. Если хочешь больше —
положи в ~/.astrym/config.json:

    {
      "virustotal": "...",
      "abuseipdb": "...",
      "shodan": "...",
      "hibp": "..."
    }

## Быстрый старт

    python3 astrym.py                            # интерактивное меню
    python3 astrym.py domain github.com          # один домен
    python3 astrym.py ip 8.8.8.8 -x -f all       # IP + все форматы
    python3 astrym.py check 1.1.1.1              # threat intel
    python3 astrym.py community                  # Louvain в графе
    python3 astrym.py stix github.com -f all     # STIX 2.1

    # REST API
    python3 astrym_serve.py --genkey
    python3 astrym_serve.py --host 0.0.0.0
