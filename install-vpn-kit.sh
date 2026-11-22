#!/bin/bash
# =====================================================================
#  Amnezia Server Kit — надстройки для сервера Amnezia (AmneziaWG)
#
#  Ставит: блокировку российских IP для клиентов VPN, AdGuard Home
#  (свой DNS, статистика по клиентам, детский режим), запрет SMTP,
#  межсетевой экран, fail2ban, автообновления, BBR и Telegram-бота
#  для управления сервером.
#
#  Нужно: Ubuntu 22.04+ / Debian 12+, AmneziaWG, установленный на этот
#  сервер через приложение Amnezia.
#
#  Запуск (на сервере, от root):
#    bash install-vpn-kit.sh --token <токен бота от @BotFather>
#  Повторный запуск безопасен: обновляет файлы, настройки сохраняются.
#  Удаление:  bash install-vpn-kit.sh --uninstall
# =====================================================================
set -Eeuo pipefail
KIT_VERSION="1.4"
AG_IP=172.29.172.253
OPTIONS_FILE=/etc/vpn-kit/options

TOKEN=""; RU_BLOCK=1; RU_DNS=1; ADGUARD=1; AUTO_REBOOT=1; BOT=1; UNINSTALL=0; YES=0; RESTORE=""; RESTORE_PASS=""

# Параметры прошлой установки: повторный запуск (обновление) их не сбрасывает
if [ -r "$OPTIONS_FILE" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      RU_BLOCK|RU_DNS|ADGUARD|AUTO_REBOOT|BOT) if [[ "$v" =~ ^[01]$ ]]; then printf -v "$k" '%s' "$v"; fi ;;
    esac
  done < "$OPTIONS_FILE"
fi

usage() { cat <<'EOF'
Использование: bash install-vpn-kit.sh [параметры]

  --token <токен>     токен Telegram-бота от @BotFather
                      (можно задать позже командой: vpn-bot-token <токен>)
  --no-ru-block       не блокировать российские IP-адреса для клиентов VPN
  --no-ru-dns         не блокировать домены .ru/.рф/.su в AdGuard — нужно, если
                      пользователи включат «российские сайты без VPN»
  --no-adguard        не ставить AdGuard Home (свой DNS, фильтрация, детский режим)
  --no-auto-reboot    не перезагружать сервер ночью после обновлений ядра
  --no-bot            не ставить Telegram-бота
  --uninstall         удалить Amnezia Server Kit (AmneziaWG и клиенты остаются)
  --restore <файл>    восстановить из зашифрованного бэкапа бота (переезд на новый сервер)
  --pass <пароль>     пароль бэкапа для --restore (иначе спросит)
  -y, --yes           не спрашивать подтверждение (для --uninstall)
  -h, --help          эта справка

Параметры --no-… запоминаются: повторный запуск (обновление) их учитывает.
Включить компонент обратно: --ru-block, --ru-dns, --adguard, --auto-reboot, --bot.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)          TOKEN="${2:-}"; shift 2 ;;
    --no-ru-block)    RU_BLOCK=0; shift ;;
    --no-ru-dns)      RU_DNS=0; shift ;;
    --no-adguard)     ADGUARD=0; shift ;;
    --no-auto-reboot) AUTO_REBOOT=0; shift ;;
    --no-bot)         BOT=0; shift ;;
    --ru-block)       RU_BLOCK=1; shift ;;
    --ru-dns)         RU_DNS=1; shift ;;
    --adguard)        ADGUARD=1; shift ;;
    --auto-reboot)    AUTO_REBOOT=1; shift ;;
    --bot)            BOT=1; shift ;;
    --uninstall)      UNINSTALL=1; shift ;;
    --restore)        RESTORE="${2:-}"; shift 2 ;;
    --pass)           RESTORE_PASS="${2:-}"; shift 2 ;;
    -y|--yes)         YES=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; echo; usage; exit 1 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }
trap 'die "Ошибка в строке $LINENO: $BASH_COMMAND"' ERR

put() {   # put <путь> <права>  < содержимое
  local dst=$1 mode=$2 tmp
  mkdir -p "$(dirname "$dst")"
  tmp="$dst.vpnkit-tmp"
  cat > "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dst"
}

# ---------------- встроенные файлы (сгенерировано build.py) ----------------
file_block_ru_sh() {
put /usr/local/sbin/block-ru.sh 755 <<'VPNKIT_EOF_FILE_BLOCK_RU_SH'
#!/bin/bash
# Запрет доступа к российским IP для клиентов VPN (Amnezia в Docker).
# Использование: block-ru.sh        — обновить список и включить блокировку
#                block-ru.sh stop   — снять блокировку
set -euo pipefail

SET=ru_v4
CACHE=/var/lib/block-ru/ru_v4.txt
URLS=(
  "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone"
  "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt"
  "https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix"
)
CIDR_RE='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'

WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "Не найден внешний интерфейс" >&2; exit 1; }
if iptables -n -L DOCKER-USER >/dev/null 2>&1; then CHAIN=DOCKER-USER; else CHAIN=FORWARD; fi
# Только НОВЫЕ исходящие соединения: ответы клиентам с российскими IP не трогаем
RULE=(-o "$WAN" -m conntrack --ctstate NEW -m set --match-set "$SET" dst -j REJECT)

if [ "${1:-}" = "stop" ]; then
  while iptables -D "$CHAIN" "${RULE[@]}" 2>/dev/null; do :; done
  ipset destroy "$SET" 2>/dev/null || true
  echo "Блокировка снята"; exit 0
fi

# 1. Свежий список российских сетей (при неудаче — сохранённый)
mkdir -p "$(dirname "$CACHE")"
TMPF=$(mktemp)
for u in "${URLS[@]}"; do
  if curl -fsSL --max-time 90 "$u" | grep -oE "$CIDR_RE" > "$TMPF" \
     && [ "$(wc -l < "$TMPF")" -gt 1000 ]; then
    mv "$TMPF" "$CACHE"; echo "Источник: $u"; break
  fi
done
rm -f "$TMPF"
[ -s "$CACHE" ] || { echo "Нет списка российских сетей" >&2; exit 1; }

# 2. Атомарно обновляем ipset
ipset create -exist "$SET" hash:net family inet maxelem 131072
ipset create -exist "${SET}_new" hash:net family inet maxelem 131072
ipset flush "${SET}_new"
sed "s/^/add ${SET}_new /" "$CACHE" | ipset restore -exist
ipset swap "${SET}_new" "$SET"
ipset destroy "${SET}_new"

# 3. Правило (добавляется один раз)
iptables -C "$CHAIN" "${RULE[@]}" 2>/dev/null || iptables -I "$CHAIN" 1 "${RULE[@]}"

echo "OK: $(wc -l < "$CACHE") сетей RU, цепочка $CHAIN, интерфейс $WAN"
VPNKIT_EOF_FILE_BLOCK_RU_SH
}

file_block_ru_service() {
put /etc/systemd/system/block-ru.service 644 <<'VPNKIT_EOF_FILE_BLOCK_RU_SERVICE'
[Unit]
Description=Block Russian IPs for VPN clients
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/block-ru.sh

[Install]
WantedBy=multi-user.target docker.service
VPNKIT_EOF_FILE_BLOCK_RU_SERVICE
}

file_block_ru_timer() {
put /etc/systemd/system/block-ru.timer 644 <<'VPNKIT_EOF_FILE_BLOCK_RU_TIMER'
[Unit]
Description=Weekly update of Russian IP list

[Timer]
OnCalendar=weekly
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
VPNKIT_EOF_FILE_BLOCK_RU_TIMER
}

file_vpn_net_sh() {
put /usr/local/sbin/vpn-net.sh 755 <<'VPNKIT_EOF_FILE_VPN_NET_SH'
#!/bin/bash
# Сетевые правила для VPN-клиентов Amnezia (идемпотентно, запускается раз в минуту):
#  1) запрет исходящего SMTP (порт 25) — защита от спама через VPN
#  2) BBR (приложение Amnezia при установке протоколов может включить hybla)
#  3) DNS клиентов -> AdGuard Home; если AdGuard недоступен — перенаправление снимается
#  4) AdGuard видит реальный IP каждого клиента (без маскарада для DNS + обратные маршруты),
#     синхронизация клиентов VPN -> «Клиенты» AdGuard
#  5) детский режим: клиентам из kids-ips.txt закрыт DNS-over-TLS (853), чтобы не обходили фильтр
#  6) клиенты, отключённые в боте (blocked-ips.txt): весь трафик DROP
set -uo pipefail
ADGUARD_IP=172.29.172.253
ADGUARD_NAME=adguardhome
NET=amnezia-dns-net
SYNC=/usr/local/sbin/adguard-sync-clients
KIDS_FILE=/var/lib/vpn-bot/kids-ips.txt

WAN=$(ip -4 route show default | awk '{print $5; exit}')
[ -n "$WAN" ] || { echo "Не найден внешний интерфейс" >&2; exit 1; }

# 1. SMTP
if iptables -n -L DOCKER-USER >/dev/null 2>&1; then CHAIN=DOCKER-USER; else CHAIN=FORWARD; fi
SMTP=(-o "$WAN" -p tcp --dport 25 -j REJECT --reject-with tcp-reset)
iptables -C "$CHAIN" "${SMTP[@]}" 2>/dev/null || iptables -I "$CHAIN" 1 "${SMTP[@]}"

# 2. BBR
[ "$(sysctl -n net.ipv4.tcp_congestion_control)" = bbr ] || sysctl -q -w net.ipv4.tcp_congestion_control=bbr

# 3. Жив ли AdGuard
ag_ok=0
if [ "$(docker inspect -f '{{.State.Running}}' "$ADGUARD_NAME" 2>/dev/null)" = true ] \
   && timeout 2 bash -c "</dev/tcp/$ADGUARD_IP/53" 2>/dev/null; then ag_ok=1; fi
AG_PID=$(docker inspect -f '{{.State.Pid}}' "$ADGUARD_NAME" 2>/dev/null || echo 0)
BRIDGE=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$NET" 2>/dev/null)
[ -n "$BRIDGE" ] || BRIDGE=amn0

# Синхронизация клиентов с AdGuard (обновляет и список детского режима)
if [ "$ag_ok" = 1 ] && [ -x "$SYNC" ]; then "$SYNC" || true; fi
KIDS=$(grep -E '^[0-9.]+$' "$KIDS_FILE" 2>/dev/null | tr '\n' ' ')
BLOCKED=$(grep -E '^[0-9.]+$' /var/lib/vpn-bot/blocked-ips.txt 2>/dev/null | tr '\n' ' ')

# Собираем VPN-интерфейсы: контейнер, интерфейс, подсеть клиентов, IP контейнера в сети Amnezia
ENTRIES=()
for c in $(docker ps --format '{{.Names}}' | grep '^amnezia-' | grep -v '^amnezia-dns'); do
  CIP=$(docker inspect -f "{{with index .NetworkSettings.Networks \"$NET\"}}{{.IPAddress}}{{end}}" "$c" 2>/dev/null)
  for ifc in $(docker exec "$c" ls /sys/class/net 2>/dev/null | grep -E '^(awg|wg|tun)[0-9]+$'); do
    SUBNET=$(docker exec "$c" ip -4 route show dev "$ifc" proto kernel 2>/dev/null | awk '{print $1; exit}')
    ENTRIES+=("$c|$ifc|$SUBNET|$CIP")
  done
done
DUPS=$(printf '%s\n' "${ENTRIES[@]}" | cut -d'|' -f3 | grep . | sort | uniq -d)

for e in "${ENTRIES[@]}"; do
  IFS='|' read -r c ifc SUBNET CIP <<< "$e"

  # 3. DNS -> AdGuard
  for p in udp tcp; do
    R=(PREROUTING -i "$ifc" -p "$p" --dport 53 -j DNAT --to-destination "$ADGUARD_IP:53")
    if [ "$ag_ok" = 1 ]; then
      docker exec "$c" iptables -t nat -C "${R[@]}" 2>/dev/null || {
        docker exec "$c" iptables -t nat -I "${R[@]}" && echo "DNS-редирект включён: $c/$ifc/$p"; }
    else
      while docker exec "$c" iptables -t nat -D "${R[@]}" 2>/dev/null; do echo "DNS-редирект снят (AdGuard недоступен): $c/$ifc/$p"; done
    fi
  done

  # 4. Реальные IP клиентов в AdGuard (если подсеть уникальна и контейнер в сети Amnezia)
  if [ -n "$SUBNET" ] && [ -n "$CIP" ] && ! grep -qxF "$SUBNET" <<< "$DUPS"; then
    ip route replace "$SUBNET" via "$CIP" dev "$BRIDGE"                       # запасной путь через хост
    [ "$AG_PID" -gt 0 ] 2>/dev/null && nsenter -t "$AG_PID" -n ip route replace "$SUBNET" via "$CIP"
    X=(POSTROUTING -s "$SUBNET" -d "$ADGUARD_IP" -j RETURN)
    docker exec "$c" iptables -t nat -C "${X[@]}" 2>/dev/null || {
      docker exec "$c" iptables -t nat -I "${X[@]}" && echo "AdGuard видит IP клиентов: $c/$SUBNET"; }
  fi

  # 5. Детский режим: запрет DNS-over-TLS/QUIC (853); 6. отключённые в боте клиенты: DROP
  docker exec "$c" sh -c '
    iptables -N VPN-KIDS 2>/dev/null
    iptables -C FORWARD -i '"$ifc"' -j VPN-KIDS 2>/dev/null || iptables -I FORWARD -i '"$ifc"' -j VPN-KIDS
    iptables -F VPN-KIDS
    for ip in '"$KIDS"'; do
      iptables -A VPN-KIDS -s "$ip" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
      iptables -A VPN-KIDS -s "$ip" -p udp --dport 853 -j REJECT
    done
    iptables -N VPN-BLOCK 2>/dev/null
    iptables -C FORWARD -i '"$ifc"' -j VPN-BLOCK 2>/dev/null || iptables -I FORWARD -i '"$ifc"' -j VPN-BLOCK
    iptables -F VPN-BLOCK
    for ip in '"$BLOCKED"'; do iptables -A VPN-BLOCK -s "$ip" -j DROP; done' 2>/dev/null
done
exit 0
VPNKIT_EOF_FILE_VPN_NET_SH
}

file_vpn_net_service() {
put /etc/systemd/system/vpn-net.service 644 <<'VPNKIT_EOF_FILE_VPN_NET_SERVICE'
[Unit]
Description=VPN network rules (SMTP block, DNS->AdGuard, BBR)
After=docker.service network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpn-net.sh
LogLevelMax=notice

[Install]
WantedBy=multi-user.target docker.service
VPNKIT_EOF_FILE_VPN_NET_SERVICE
}

file_vpn_net_timer() {
put /etc/systemd/system/vpn-net.timer 644 <<'VPNKIT_EOF_FILE_VPN_NET_TIMER'
[Unit]
Description=Re-apply VPN network rules every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
VPNKIT_EOF_FILE_VPN_NET_TIMER
}

file_adguard_sync_clients() {
put /usr/local/sbin/adguard-sync-clients 700 <<'VPNKIT_EOF_FILE_ADGUARD_SYNC_CLIENTS'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Синхронизация клиентов VPN (AmneziaWG / WireGuard) с «Постоянными клиентами» AdGuard Home.

Каждый VPN-клиент становится клиентом AdGuard со своим IP (10.8.1.x) и именем из приложения Amnezia,
поэтому в AdGuard видна статистика и можно задавать настройки для каждого отдельно.
 - новый клиент VPN      -> добавляется в AdGuard (обычный режим)
 - клиент удалён          -> удаляется из AdGuard
 - IP отдан другому ключу -> старые настройки сбрасываются (детский режим не «переезжает» к другому человеку)
 - переименован в Amnezia -> переименовывается, если имя не меняли вручную в AdGuard
Также пишет IP клиентов в детском режиме в /var/lib/vpn-bot/kids-ips.txt (для vpn-net.sh).
"""
import base64
import fcntl
import json
import os
import subprocess
import sys
import urllib.request

ADGUARD = "http://172.29.172.253"
CRED = "/root/adguard-admin.txt"
STATE = "/var/lib/vpn-bot/adguard-clients.json"
KIDS = "/var/lib/vpn-bot/kids-ips.txt"
LOCK = "/run/adguard-sync.lock"
PROBES = [("/opt/amnezia/awg", "awg0.conf"), ("/opt/amnezia/wireguard", "wg0.conf")]
SAFESEARCH_OFF = {"enabled": False, "bing": True, "duckduckgo": True, "ecosia": True, "google": True,
                  "pixabay": True, "yandex": True, "youtube": True}


def sh(*cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout


def ag(method, path, data=None):
    creds = {}
    with open(CRED, encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                creds[k.strip()] = v.strip()
    auth = base64.b64encode(("%s:%s" % (creds.get("Login", "admin"), creds.get("Password", ""))).encode()).decode()
    req = urllib.request.Request(ADGUARD + path, method=method,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read()
    try:
        return json.loads(body) if body else {}
    except ValueError:
        return {}


def vpn_peers():
    """-> {ip: (public_key, name)} по всем VPN-контейнерам Amnezia"""
    _, out = sh("docker", "ps", "--format", "{{.Names}}")
    peers = {}
    for c in out.split():
        if not c.startswith("amnezia-") or c.startswith("amnezia-dns"):
            continue
        for d, f in PROBES:
            rc, conf = sh("docker", "exec", c, "cat", "%s/%s" % (d, f))
            if rc != 0:
                continue
            rc, tbl = sh("docker", "exec", c, "cat", d + "/clientsTable")
            names = {}
            if rc == 0 and tbl.strip():
                try:
                    names = {x.get("clientId"): (x.get("userData") or {}).get("clientName")
                             for x in json.loads(tbl)}
                except ValueError:
                    pass
            pub = None
            for line in conf.splitlines():
                s = line.strip()
                if s.startswith("["):
                    pub = None
                    continue
                k, _, v = s.partition("=")
                k, v = k.strip(), v.strip()
                if k == "PublicKey":
                    pub = v
                elif k == "AllowedIPs" and pub:
                    ip = v.split(",")[0].strip().split("/")[0]
                    name = " ".join((names.get(pub) or "VPN %s" % ip).split())[:60]
                    peers[ip] = (pub, name)
    return peers


def new_client(name, ip):
    return {"name": name, "ids": [ip], "tags": [], "use_global_settings": True,
            "use_global_blocked_services": True, "filtering_enabled": True, "parental_enabled": False,
            "safebrowsing_enabled": False, "safe_search": dict(SAFESEARCH_OFF), "blocked_services": [],
            "upstreams": [], "ignore_querylog": False, "ignore_statistics": False}


def write_if_changed(path, text):
    try:
        with open(path, encoding="utf-8") as f:
            if f.read() == text:
                return
    except FileNotFoundError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def main():
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(LOCK, "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        peers = vpn_peers()
        try:
            with open(STATE, encoding="utf-8") as f:
                state = json.load(f)
        except (FileNotFoundError, ValueError):
            state = {}
        clients = ag("GET", "/control/clients").get("clients") or []

        def by_ip(ip):
            return next((c for c in clients if ip in (c.get("ids") or [])), None)

        used = {c["name"] for c in clients}

        # 1. клиенты, которых больше нет в VPN (или IP достался другому ключу)
        for ip, st in list(state.items()):
            if ip not in peers or peers[ip][0] != st.get("pub"):
                c = by_ip(ip)
                if c:
                    ag("POST", "/control/clients/delete", {"name": c["name"]})
                    clients.remove(c)
                    used.discard(c["name"])
                    print("removed:", c["name"], ip)
                del state[ip]

        # 2. новые и переименованные
        for ip, (pub, want) in sorted(peers.items()):
            c = by_ip(ip)
            st = state.get(ip)
            if c is None:
                name = want if want not in used else "%s (%s)" % (want, ip)
                obj = new_client(name, ip)
                ag("POST", "/control/clients/add", obj)
                clients.append(obj)
                used.add(name)
                state[ip] = {"pub": pub, "name": name}
                print("added:", name, ip)
            elif st is None:
                state[ip] = {"pub": pub, "name": c["name"]}          # уже был в AdGuard — берём под управление
            elif c["name"] != st["name"]:
                st["name"] = c["name"]                                 # переименован вручную в AdGuard — не трогаем
            elif want != c["name"] and want not in used:
                data = dict(c)
                data["name"] = want
                ag("POST", "/control/clients/update", {"name": c["name"], "data": data})
                used.discard(c["name"])
                used.add(want)
                st["name"] = want
                print("renamed:", c["name"], "->", want)

        write_if_changed(STATE, json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True))
        kids = sorted(ip for ip in peers
                      if (by_ip(ip) or {}).get("parental_enabled") and not (by_ip(ip) or {}).get("use_global_settings", True))
        write_if_changed(KIDS, "".join(ip + "\n" for ip in kids))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print("adguard-sync-clients:", ex, file=sys.stderr)
        sys.exit(1)
VPNKIT_EOF_FILE_ADGUARD_SYNC_CLIENTS
}

file_bot_py() {
put /opt/vpn-bot/bot.py 644 <<'VPNKIT_EOF_FILE_BOT_PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram-панель управления VPN-сервером (Amnezia / AmneziaWG 2).

Только стандартная библиотека Python.
Конфиг:  /etc/vpn-bot/config.json  {"token": "...", "admins": [id, ...], "setup_code": "..."}
Данные:  /var/lib/vpn-bot/  (конфиги созданных клиентов, резервные копии)
"""
import base64
import collections
import fcntl
import html
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib

CONFIG_PATH = os.environ.get("VPN_BOT_CONFIG", "/etc/vpn-bot/config.json")
KIT_OPTIONS = "/etc/vpn-kit/options"   # параметры установки (их учитывает повторный запуск установщика)
DATA_DIR = "/var/lib/vpn-bot"
CLIENTS_DIR = os.path.join(DATA_DIR, "clients")
BACKUP_DIR = os.path.join(DATA_DIR, "backup")
TRAFFIC_PATH = os.path.join(DATA_DIR, "traffic.json")   # помесячный учёт, пишется часто — отдельно от config.json

GB = 1024 ** 3

AWG_CONTAINER = "amnezia-awg2"
AWG_DIR = "/opt/amnezia/awg"
AWG_CONF = AWG_DIR + "/awg0.conf"
AWG_TABLE = AWG_DIR + "/clientsTable"
AWG_PSK = AWG_DIR + "/wireguard_psk.key"
AWG_SERVER_PUB = AWG_DIR + "/wireguard_server_public_key.key"
AWG_IF = "awg0"
CLIENT_DNS = "1.1.1.1, 1.0.0.1"   # всё равно перенаправляется в AdGuard на сервере
CLIENT_MTU = "1376"
ONLINE_SEC = 180                   # «онлайн», если рукопожатие было не раньше N секунд назад
REPORT_HOUR = 9                    # час отправки регулярного отчёта (время сервера)

ADGUARD_CONTAINER = "adguardhome"
ADGUARD_IP = "172.29.172.253"
ADGUARD_CRED = "/root/adguard-admin.txt"
RU_DNS_RULES = ["||ru^", "||xn--p1ai^", "||su^"]
RU_DNS_COMMENT = "! Российские доменные зоны (дополнение к блокировке по IP)"

RU_SCRIPT = "/usr/local/sbin/block-ru.sh"
RU_CACHE = "/var/lib/block-ru/ru_v4.txt"
VPN_NET_SCRIPT = "/usr/local/sbin/vpn-net.sh"
SYNC_SCRIPT = "/usr/local/sbin/adguard-sync-clients"
SAFESEARCH_ALL = {"bing": True, "duckduckgo": True, "ecosia": True, "google": True,
                  "pixabay": True, "yandex": True, "youtube": True}
AG_STATE = os.path.join(DATA_DIR, "adguard-clients.json")
AG_LOCK = "/run/adguard-sync.lock"
BLOCKED_FILE = os.path.join(DATA_DIR, "blocked-ips.txt")   # читает vpn-net.sh

# Обнаружение одного конфига на нескольких устройствах
SHARE_POLL = 3            # опрос состояния клиентов, сек
SHARE_WINDOW = 300        # окно анализа, сек
# Эксперимент (за 5 мин): 1 устройство — 0 смен адреса / 3 рукопожатия;
# 2 устройства — от 4 / 10 (одно активно, другое в фоне) до 38 / 14 (оба активны).
SHARE_MIN_EP_CHANGES = 3  # смен адреса за окно И …
SHARE_MIN_HANDSHAKES = 7  # … рукопожатий за окно
SHARE_EP_ALONE = 10       # или столько смен адреса без учёта рукопожатий
SHARE_REALERT = 3600      # повторное уведомление по тому же клиенту — не чаще раза в час
SHARE_MUTE = 86400        # «Игнорировать» — на сутки

e = html.escape


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


# ====================== конфиг ======================
def load_cfg():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


CFG = load_cfg()
ADMINS = set(int(x) for x in CFG.get("admins", []))
API = "https://api.telegram.org/bot%s/" % CFG.get("token", "")

# Параметры AmneziaWG определяет установщик (install-vpn-kit.sh) и пишет в конфиг
AWG_CONTAINER = CFG.get("awg_container", AWG_CONTAINER)
AWG_DIR = CFG.get("awg_dir", AWG_DIR)
AWG_IF = CFG.get("awg_if", AWG_IF)
AWG_CONF = "%s/%s.conf" % (AWG_DIR, AWG_IF)
AWG_TABLE = AWG_DIR + "/clientsTable"
AWG_PSK = AWG_DIR + "/wireguard_psk.key"
AWG_SERVER_PUB = AWG_DIR + "/wireguard_server_public_key.key"


def save_cfg():
    CFG["admins"] = sorted(ADMINS)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(CFG, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


def set_kit_option(key, value):
    """Запомнить выбор из меню бота, чтобы обновление установщиком его не сбросило."""
    try:
        with open(KIT_OPTIONS, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return   # установка версии 1.0 — файла параметров ещё нет
    out, found = [], False
    for line in lines:
        if line.split("=", 1)[0] == key:
            line, found = "%s=%s" % (key, value), True
        out.append(line)
    if not found:
        out.append("%s=%s" % (key, value))
    tmp = KIT_OPTIONS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, KIT_OPTIONS)


# ====================== данные по клиентам (срок, лимит) ======================
# В config.json под ключом "clients": {pub: {"expires": "YYYY-MM-DD"|None,
#   "limit_gb": число|None, "auto_off": "expired"|"limit"|None, "warned": "YYYY-MM-DD"|None}}
def cdata(pub):
    return CFG.get("clients", {}).get(pub, {})


def set_cdata(pub, **kw):
    c = CFG.setdefault("clients", {}).setdefault(pub, {})
    for k, v in kw.items():
        if v is None and k in c:
            del c[k]
        elif v is not None:
            c[k] = v
    if not c:
        CFG["clients"].pop(pub, None)
    save_cfg()


# ====================== помесячный учёт трафика ======================
def cur_month():
    return time.strftime("%Y-%m")


def load_traffic():
    try:
        with open(TRAFFIC_PATH, encoding="utf-8") as f:
            t = json.load(f)
        return t if isinstance(t, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def save_traffic(t):
    tmp = TRAFFIC_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(t, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, TRAFFIC_PATH)


def account_delta(prev_raw, cur_raw):
    """Прирост счётчика с учётом обнуления (перезапуск контейнера сбрасывает счётчики awg в 0)."""
    return cur_raw - prev_raw if cur_raw >= prev_raw else cur_raw


def roll_month(entry, month, cur_rx, cur_tx):
    """Обновить запись трафика одного клиента. Новый месяц (или первая запись) — счёт с нуля."""
    if not entry or entry.get("month") != month:
        return {"month": month, "rx": 0, "tx": 0, "last_rx": cur_rx, "last_tx": cur_tx}
    return {"month": month,
            "rx": entry["rx"] + account_delta(entry["last_rx"], cur_rx),
            "tx": entry["tx"] + account_delta(entry["last_tx"], cur_tx),
            "last_rx": cur_rx, "last_tx": cur_tx}


def used_bytes(pub, traffic=None):
    """Трафик клиента за текущий месяц (rx+tx), байт."""
    t = (traffic if traffic is not None else load_traffic()).get(pub)
    if not t or t.get("month") != cur_month():
        return 0
    return t.get("rx", 0) + t.get("tx", 0)


def account_traffic():
    """Снять текущие счётчики по всем пирам и обновить помесячный учёт. -> {pub: использовано_байт}."""
    dump = awg_dump()
    traffic = load_traffic()
    month = cur_month()
    changed = False
    for pub, d in dump.items():
        new = roll_month(traffic.get(pub), month, d.get("rx", 0), d.get("tx", 0))
        if new != traffic.get(pub):
            traffic[pub] = new
            changed = True
    if changed:
        save_traffic(traffic)
    return {pub: (t.get("rx", 0) + t.get("tx", 0)) for pub, t in traffic.items() if t.get("month") == month}


# ====================== Telegram API ======================
def tg(method, params=None, files=None, timeout=30):
    url = API + method
    params = {k: v for k, v in (params or {}).items() if v is not None}
    if files:
        boundary = uuid.uuid4().hex
        body = bytearray()
        for k, v in params.items():
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            body += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                     % (boundary, k, v)).encode()
        for k, (fname, data, ctype) in files.items():
            body += ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                     'Content-Type: %s\r\n\r\n' % (boundary, k, fname, ctype)).encode()
            body += data + b"\r\n"
        body += ("--%s--\r\n" % boundary).encode()
        req = urllib.request.Request(url, data=bytes(body), headers={
            "Content-Type": "multipart/form-data; boundary=" + boundary})
    else:
        req = urllib.request.Request(url, data=json.dumps(params).encode(),
                                     headers={"Content-Type": "application/json"})
    for attempt in range(3):   # обрывы связи с Telegram бывают — повторяем
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as ex:
            try:
                return json.loads(ex.read())
            except Exception:
                return {"ok": False, "description": str(ex)}
        except (urllib.error.URLError, OSError) as ex:
            if attempt == 2:
                return {"ok": False, "description": "network: %s" % ex}
            time.sleep(1 + attempt)


def kb_markup(kb):
    return {"inline_keyboard": kb} if kb else None


def send(chat, text, kb=None):
    r = tg("sendMessage", {"chat_id": chat, "text": text, "parse_mode": "HTML",
                           "disable_web_page_preview": True, "reply_markup": kb_markup(kb)})
    if not r.get("ok"):
        log("sendMessage failed:", r.get("description"))
    return r


def edit(chat, mid, text, kb=None):
    r = tg("editMessageText", {"chat_id": chat, "message_id": mid, "text": text,
                               "parse_mode": "HTML", "disable_web_page_preview": True,
                               "reply_markup": kb_markup(kb)})
    if not r.get("ok") and "not modified" not in r.get("description", ""):
        send(chat, text, kb)


def send_file(chat, fname, data, caption=None, ctype="text/plain"):
    return tg("sendDocument", {"chat_id": chat, "caption": caption, "parse_mode": "HTML"},
              files={"document": (fname, data, ctype)}, timeout=60)


def send_photo(chat, data, caption=None):
    return tg("sendPhoto", {"chat_id": chat, "caption": caption, "parse_mode": "HTML"},
              files={"photo": ("qr.png", data, "image/png")}, timeout=60)


def notify_admins(text):
    for a in ADMINS:
        send(a, text)


# ====================== shell ======================
def run(cmd, inp=None, timeout=60, env=None):
    kw = {"input": inp} if inp is not None else {"stdin": subprocess.DEVNULL}
    if env is not None:
        kw["env"] = env
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as ex:
        return 127, "", str(ex)


def dexec(*args, inp=None, timeout=30):
    cmd = ["docker", "exec"] + (["-i"] if inp is not None else []) + [AWG_CONTAINER] + list(args)
    return run(cmd, inp=inp, timeout=timeout)


# ====================== форматирование ======================
def hb(n):
    n = float(n or 0)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or u == "ТБ":
            return ("%.0f %s" if u == "Б" else "%.1f %s") % (n, u)
        n /= 1024


def ago(ts):
    if not ts:
        return "не подключался"
    d = int(time.time() - ts)
    if d < 60:
        return "%d сек назад" % d
    if d < 3600:
        return "%d мин назад" % (d // 60)
    if d < 86400:
        return "%d ч %d мин назад" % (d // 3600, d % 3600 // 60)
    return "%d дн назад" % (d // 86400)


def dur(sec):
    sec = int(sec)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return ("%d д %d ч" % (d, h)) if d else ("%d ч %d мин" % (h, m)) if h else ("%d мин" % m)


TR = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
              ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p",
               "r", "s", "t", "u", "f", "h", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]))


def conf_filename(name, ip):
    s = "".join(TR.get(ch.lower(), ch) for ch in name)
    s = re.sub(r"[^A-Za-z0-9_-]+", "", s)[:11]   # имя туннеля в клиентах WG — до 15 символов
    return "awg-%s.conf" % (s or ip.split(".")[-1])


# ====================== AmneziaWG ======================
_awg_lock = threading.Lock()


_container_pid = 0


def container_pid():
    """PID контейнера VPN (кешируется). Через него файлы контейнера видны на хосте как /proc/<pid>/root/…"""
    global _container_pid
    if not _container_pid:
        rc, out, _ = run(["docker", "inspect", "-f", "{{.State.Pid}}", AWG_CONTAINER])
        _container_pid = int(out.strip() or 0) if rc == 0 else 0
    return _container_pid


def container_pid_reset():
    global _container_pid
    _container_pid = 0


def read_file(path):
    # быстрый путь: файл контейнера читаем прямо с хоста через /proc/<pid>/root (без docker exec)
    pid = container_pid()
    if pid:
        try:
            with open("/proc/%d/root%s" % (pid, path), encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            container_pid_reset()   # контейнер перезапущен — PID устарел, уйдём на docker exec
    rc, out, err = dexec("cat", path)
    if rc != 0:
        raise RuntimeError("не удалось прочитать %s: %s" % (path, err.strip()))
    return out


def write_file(path, content):
    rc, _, err = dexec("sh", "-c", 'cat > "%s"' % path, inp=content)
    if rc != 0:
        raise RuntimeError("не удалось записать %s: %s" % (path, err.strip()))


def split_blocks(text):
    blocks, cur = [], []
    for line in text.splitlines(keepends=True):
        if line.strip().startswith("[") and cur:
            blocks.append("".join(cur))
            cur = []
        cur.append(line)
    if cur:
        blocks.append("".join(cur))
    return blocks


def block_name(b):
    first = b.strip().splitlines()[0].strip() if b.strip() else ""
    return first[1:-1] if first.startswith("[") and first.endswith("]") else ""


def block_items(b):
    items = []
    for line in b.splitlines()[1:]:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            items.append((k.strip(), v.strip()))
    return items


def awg_conf():
    conf = read_file(AWG_CONF)
    iface, peers = [], []
    for b in split_blocks(conf):
        n = block_name(b)
        if n == "Interface":
            iface = block_items(b)
        elif n == "Peer":
            peers.append(dict(block_items(b)))
    return conf, iface, peers


def load_table():
    try:
        t = json.loads(read_file(AWG_TABLE) or "[]")
        return t if isinstance(t, list) else []
    except (json.JSONDecodeError, RuntimeError):
        return []


def save_table(t):
    write_file(AWG_TABLE, json.dumps(t, indent=4, ensure_ascii=False) + "\n")


def awg_dump():
    rc, out, _ = dexec("awg", "show", AWG_IF, "dump")
    peers = {}
    for line in out.strip().splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 8:
            peers[f[0]] = {"endpoint": f[2], "hs": int(f[4] or 0), "rx": int(f[5] or 0), "tx": int(f[6] or 0)}
    return peers


def uapi_peers():
    """Состояние клиентов напрямую из управляющего сокета amneziawg-go (дёшево, без docker exec).
    -> {pub_base64: {"endpoint": "ip:port", "hs": unix_time, "rx": байт, "tx": байт}}"""
    buf = b""
    for attempt in range(2):
        pid = container_pid()
        # в Alpine /var/run -> /run (абсолютная ссылка), поэтому путь через /run
        path = "/proc/%d/root/run/amneziawg/%s.sock" % (pid, AWG_IF)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(path)
            s.sendall(b"get=1\n\n")
            while not buf.endswith(b"\n\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            s.close()
            break
        except OSError:
            container_pid_reset()
            buf = b""
            if attempt:
                raise
    peers, cur = {}, None
    for line in buf.decode(errors="replace").splitlines():
        k, _, v = line.partition("=")
        if k == "public_key":
            cur = {"endpoint": "", "hs": 0, "rx": 0, "tx": 0}
            peers[base64.b64encode(bytes.fromhex(v)).decode()] = cur
        elif cur is not None:
            if k == "endpoint":
                cur["endpoint"] = v
            elif k == "last_handshake_time_sec":
                cur["hs"] = int(v or 0)
            elif k == "rx_bytes":
                cur["rx"] = int(v or 0)
            elif k == "tx_bytes":
                cur["tx"] = int(v or 0)
    return peers


def conf_path(pub):
    return os.path.join(CLIENTS_DIR, pub.replace("/", "_").replace("+", "-").rstrip("=") + ".conf")


def get_clients():
    _, _, peers = awg_conf()
    table = {c.get("clientId"): c.get("userData", {}) for c in load_table()}
    try:
        dump = uapi_peers()           # дёшево, без docker exec
    except Exception:
        dump = awg_dump()             # запасной путь (нет сокета — например, модуль ядра)
    res = []
    for p in peers:
        pub = p.get("PublicKey", "")
        ud, d = table.get(pub, {}), dump.get(pub, {})
        ip = p.get("AllowedIPs", "").split(",")[0].strip().split("/")[0]
        try:
            ip_sort = int(ipaddress.ip_address(ip))
        except ValueError:
            ip_sort = 0
        res.append({"pub": pub, "name": ud.get("clientName") or "без имени", "ip": ip, "ip_sort": ip_sort,
                    "created": ud.get("creationDate", ""), "hs": d.get("hs", 0), "rx": d.get("rx", 0),
                    "tx": d.get("tx", 0), "endpoint": d.get("endpoint") or "(none)",
                    "has_conf": os.path.exists(conf_path(pub))})
    return sorted(res, key=lambda c: c["ip_sort"])


def backup_awg():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    for src, name in ((AWG_CONF, "awg0.conf"), (AWG_TABLE, "clientsTable")):
        try:
            data = read_file(src)
        except RuntimeError:
            continue
        p = os.path.join(BACKUP_DIR, "%s.%s" % (name, ts))
        with open(p, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(p, 0o600)
    files = sorted(os.listdir(BACKUP_DIR))
    for old in files[:-40]:   # храним последние ~20 пар
        os.remove(os.path.join(BACKUP_DIR, old))


def server_ip():
    if CFG.get("server_ip"):
        return CFG["server_ip"]
    _, out, _ = run(["ip", "-4", "-o", "route", "get", "1.1.1.1"])
    m = re.search(r"\bsrc (\S+)", out)
    if not m:
        raise RuntimeError("не удалось определить внешний IP сервера")
    return m.group(1)


def create_client(name):
    with _awg_lock:
        conf, iface_items, peers = awg_conf()
        iface = dict(iface_items)
        addr = iface["Address"].split(",")[0].strip()
        net = ipaddress.ip_network(addr, strict=False)
        used = {str(ipaddress.ip_interface(addr).ip)}
        for p in peers:
            for a in p.get("AllowedIPs", "").split(","):
                if a.strip():
                    used.add(str(ipaddress.ip_interface(a.strip()).ip))
        ip = next((str(h) for h in net.hosts() if str(h) not in used), None)
        if not ip:
            raise RuntimeError("в подсети %s нет свободных адресов" % net)

        priv, pub = gen_keys()
        psk = read_file(AWG_PSK).strip()
        spub = read_file(AWG_SERVER_PUB).strip()

        backup_awg()
        peer_block = "[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n" % (pub, psk, ip)
        write_file(AWG_CONF, conf.rstrip("\n") + "\n\n" + peer_block + "\n")
        rc, _, err = dexec("awg", "set", AWG_IF, "peer", pub, "preshared-key", AWG_PSK,
                           "allowed-ips", ip + "/32")
        if rc:
            write_file(AWG_CONF, conf)   # откат
            raise RuntimeError("awg set: " + err.strip())

        table = load_table()
        table.append({"clientId": pub, "userData": {
            "allowed_ips": ip + "/32", "clientName": name,
            "creationDate": time.strftime("%a %b %d %H:%M:%S %Y")}})
        save_table(table)

        text = build_client_conf(priv, ip, iface_items, spub, psk)
        save_client_conf(pub, text)
        return {"pub": pub, "ip": ip, "conf": text}


def gen_keys():
    rc, priv, err = dexec("awg", "genkey")
    priv = priv.strip()
    if rc or not priv:
        raise RuntimeError("awg genkey: " + err.strip())
    rc, pub, err = dexec("awg", "pubkey", inp=priv + "\n")
    pub = pub.strip()
    if rc or not pub:
        raise RuntimeError("awg pubkey: " + err.strip())
    return priv, pub


def build_client_conf(priv, ip, iface_items, spub, psk):
    iface = dict(iface_items)
    skip = {"PrivateKey", "Address", "ListenPort", "MTU", "DNS", "PreUp", "PostUp", "PreDown",
            "PostDown", "SaveConfig", "Table", "FwMark"}
    lines = ["[Interface]", "PrivateKey = " + priv, "Address = %s/32" % ip,
             "DNS = " + CLIENT_DNS, "MTU = " + CLIENT_MTU]
    lines += ["%s = %s" % (k, v) for k, v in iface_items if k not in skip]
    lines += ["", "[Peer]", "PublicKey = " + spub, "PresharedKey = " + psk,
              "AllowedIPs = 0.0.0.0/0, ::/0",
              "Endpoint = %s:%s" % (server_ip(), iface.get("ListenPort")),
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def save_client_conf(pub, text):
    os.makedirs(CLIENTS_DIR, mode=0o700, exist_ok=True)
    with open(conf_path(pub), "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(conf_path(pub), 0o600)


# ---------- родной конфиг AmneziaVPN (vpn://), с именем сервера ----------
# Формат: "vpn://" + base64url(4 байта длины JSON (big-endian) + zlib(JSON)).
# Имя, которое видит пользователь в приложении, — верхнее поле "description".
SRV_NAME_DEFAULT = "AmneziaWG"
# базовые ключи [Interface] WireGuard — у них в vpn:// свои поля (client_priv_key/client_ip/mtu/dns),
# поэтому их НЕ дублируем; всё остальное (параметры AmneziaWG) переносим как есть
IFACE_STD_KEYS = {"PrivateKey", "Address", "DNS", "MTU", "ListenPort"}


def srv_name():
    return (CFG.get("server_name") or "").strip() or SRV_NAME_DEFAULT


def _conf_sections(conf_text):
    iface, peer = {}, {}
    for b in split_blocks(conf_text):
        n = block_name(b)
        if n == "Interface":
            iface = dict(block_items(b))
        elif n == "Peer":
            peer = dict(block_items(b))
    return iface, peer


def build_vpn_uri(conf_text, name):
    """Собрать vpn://-ссылку AmneziaVPN из текста клиентского .conf, с именем сервера name."""
    iface, peer = _conf_sections(conf_text)
    host, _, port = peer.get("Endpoint", "").rpartition(":")
    dns = [d.strip() for d in iface.get("DNS", CLIENT_DNS).split(",") if d.strip()]
    allowed = [a.strip() for a in peer.get("AllowedIPs", "0.0.0.0/0, ::/0").split(",") if a.strip()]
    last = {
        "allowed_ips": allowed,
        "client_ip": iface.get("Address", "").split(",")[0].strip(),
        "client_priv_key": iface.get("PrivateKey", ""),
        "config": conf_text,
        "hostName": host,
        "mtu": iface.get("MTU", CLIENT_MTU),
        "persistent_keep_alive": peer.get("PersistentKeepalive", "25"),
        "port": int(port) if port.isdigit() else port,
        "psk_key": peer.get("PresharedKey", ""),
        "server_pub_key": peer.get("PublicKey", ""),
    }
    # Все параметры AmneziaWG из [Interface] (кроме базовых WG) — отдельными полями,
    # как делает само приложение: иначе оно пересобирает туннель без обфускации AWG 2.0
    # (S3/S4, H1–H4, HeaderProtectionKey, Rekey*, RandomTrailers, DisableCookies …) и не подключается.
    for k, v in iface.items():
        if k not in IFACE_STD_KEYS:
            last[k] = v
    awg = {"isThirdPartyConfig": True, "last_config": json.dumps(last, ensure_ascii=False),
           "port": str(port), "transport_proto": "udp"}
    outer = {
        "containers": [{"awg": awg, "container": "amnezia-awg"}],
        "defaultContainer": "amnezia-awg",
        "description": name,
        "dns1": dns[0] if dns else "1.1.1.1",
        "dns2": dns[1] if len(dns) > 1 else "1.0.0.1",
        "format_version": 1,
        "hostName": host,
    }
    js = json.dumps(outer, ensure_ascii=False).encode()
    blob = struct.pack(">I", len(js)) + zlib.compress(js, 9)
    return "vpn://" + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def decode_vpn_uri(uri):
    """Обратное преобразование (для тестов и самопроверки)."""
    raw = uri[len("vpn://"):]
    raw += "=" * (-len(raw) % 4)
    blob = base64.urlsafe_b64decode(raw)
    return json.loads(zlib.decompress(blob[4:]).decode())


def peer_ip(peer):
    return peer.get("AllowedIPs", "").split(",")[0].strip().split("/")[0]


def rekey_client(pub):
    """Новый ключ тому же клиенту (имя и IP сохраняются). Все копии старого конфига перестают работать."""
    with _awg_lock:
        conf, iface_items, peers = awg_conf()
        peer = next((p for p in peers if p.get("PublicKey") == pub), None)
        if not peer:
            raise RuntimeError("клиент не найден в конфигурации")
        ip = peer_ip(peer)
        priv, newpub = gen_keys()
        psk = read_file(AWG_PSK).strip()
        spub = read_file(AWG_SERVER_PUB).strip()
        backup_awg()
        out = []
        for b in split_blocks(conf):
            if block_name(b) == "Peer" and dict(block_items(b)).get("PublicKey") == pub:
                b = re.sub(r"(?m)^(\s*PublicKey\s*=\s*).*$", lambda m: m.group(1) + newpub, b)
            out.append(b)
        write_file(AWG_CONF, "".join(out))
        dexec("awg", "set", AWG_IF, "peer", pub, "remove")
        blocked = pub in CFG.get("blocked", [])
        if not blocked:
            rc, _, err = dexec("awg", "set", AWG_IF, "peer", newpub, "preshared-key", AWG_PSK,
                               "allowed-ips", ip + "/32")
            if rc:
                raise RuntimeError("awg set: " + err.strip())
        table = load_table()
        for t in table:
            if t.get("clientId") == pub:
                t["clientId"] = newpub
        save_table(table)
        try:
            os.remove(conf_path(pub))
        except FileNotFoundError:
            pass
        text = build_client_conf(priv, ip, iface_items, spub, psk)
        save_client_conf(newpub, text)
    # перенос состояния на новый ключ
    if blocked:
        CFG["blocked"] = [newpub if p == pub else p for p in CFG.get("blocked", [])]
    CFG.get("share_mute", {}).pop(pub, None)
    cd = CFG.get("clients", {}).pop(pub, None)       # срок и лимит переносим на новый ключ
    if cd:
        CFG.setdefault("clients", {})[newpub] = cd
    save_cfg()
    tr = load_traffic()                              # и накопленный за месяц трафик
    if pub in tr:
        tr[newpub] = tr.pop(pub)
        save_traffic(tr)
    ag_state_repub(ip, newpub)   # чтобы синхронизация AdGuard не сбросила настройки (детский режим)
    return {"pub": newpub, "ip": ip, "conf": text}


def ag_state_repub(ip, newpub):
    try:
        with open(AG_LOCK, "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            with open(AG_STATE, encoding="utf-8") as f:
                st = json.load(f)
            if ip in st:
                st[ip]["pub"] = newpub
                tmp = AG_STATE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(st, f, indent=2, ensure_ascii=False, sort_keys=True)
                os.chmod(tmp, 0o600)
                os.replace(tmp, AG_STATE)
    except (FileNotFoundError, ValueError):
        pass


# ---------- отключение клиентов ----------
def is_blocked(pub):
    return pub in CFG.get("blocked", [])


def write_blocked_file():
    """IP отключённых клиентов -> файл для vpn-net.sh (DROP в контейнере VPN)"""
    bl = set(CFG.get("blocked", []))
    ips = []
    if bl:
        _, _, peers = awg_conf()
        ips = sorted(peer_ip(p) for p in peers if p.get("PublicKey") in bl)
    text = "".join(ip + "\n" for ip in ips)
    try:
        with open(BLOCKED_FILE, encoding="utf-8") as f:
            if f.read() == text:
                return
    except FileNotFoundError:
        pass
    with open(BLOCKED_FILE + ".tmp", "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(BLOCKED_FILE + ".tmp", BLOCKED_FILE)


def enforce_blocked():
    """Отключённые клиенты не должны быть в живом интерфейсе (например, после перезапуска контейнера)"""
    bl = set(CFG.get("blocked", []))
    if not bl:
        return
    for pub in awg_dump():
        if pub in bl:
            dexec("awg", "set", AWG_IF, "peer", pub, "remove")


def set_blocked(pub, on):
    bl = set(CFG.get("blocked", []))
    if on:
        bl.add(pub)
    else:
        bl.discard(pub)
    CFG["blocked"] = sorted(bl)
    save_cfg()
    write_blocked_file()
    if on:
        dexec("awg", "set", AWG_IF, "peer", pub, "remove")
    else:
        c = find_client(pub)
        if c:
            dexec("awg", "set", AWG_IF, "peer", pub, "preshared-key", AWG_PSK, "allowed-ips", c["ip"] + "/32")
    run([VPN_NET_SCRIPT], timeout=60)


# ====================== срок действия и лимит трафика ======================
def today_str():
    return time.strftime("%Y-%m-%d")


def is_expired(cd, today=None):
    exp = cd.get("expires")
    return bool(exp) and (today or today_str()) > exp


def is_over_limit(cd, used):
    lim = cd.get("limit_gb")
    return bool(lim) and used >= lim * GB


def auto_disable(pub, reason):
    """Отключить клиента автоматически (истёк срок/лимит) и уведомить админов."""
    set_cdata(pub, auto_off=reason)
    if pub not in CFG.get("blocked", []):
        set_blocked(pub, True)
    c = find_client(pub)
    name = e(c["name"]) if c else pub[:8]
    if reason == "expired":
        txt = "⛔ Клиент <b>%s</b> отключён: истёк срок действия." % name
        kb = [[btn("➕ Продлить 30 дней", "cext:" + pub), btn("👤 Клиент", "c:" + pub)]]
    else:
        txt = "⛔ Клиент <b>%s</b> отключён: исчерпан месячный лимит трафика." % name
        kb = [[btn("♻️ Сбросить лимит", "clrst:" + pub), btn("👤 Клиент", "c:" + pub)]]
    log("auto-disable:", reason, c["name"] if c else pub[:8])
    for a in ADMINS:
        send(a, txt, kb)


def check_access(used):
    """Проверка сроков и лимитов. used: {pub: байт за текущий месяц}. Вызывается раз в минуту."""
    today = today_str()
    tomorrow = time.strftime("%Y-%m-%d", time.localtime(time.time() + 86400))
    blocked = set(CFG.get("blocked", []))
    for pub, cd in list(CFG.get("clients", {}).items()):
        u = used.get(pub, 0)
        expired, over = is_expired(cd, today), is_over_limit(cd, u)
        off = cd.get("auto_off")
        if off:
            if not expired and not over:   # срок продлили или начался новый месяц — вернуть доступ
                set_cdata(pub, auto_off=None)
                if pub in blocked:
                    set_blocked(pub, False)
                c = find_client(pub)
                notify_admins("✅ Клиент <b>%s</b>: доступ восстановлен (%s)." % (
                    e(c["name"]) if c else pub[:8], "срок продлён" if off == "expired" else "новый месяц"))
            continue
        if pub in blocked:
            continue                        # отключён вручную админом — автоматику не применяем
        if expired:
            auto_disable(pub, "expired")
        elif over:
            auto_disable(pub, "limit")
        elif cd.get("expires") == tomorrow and cd.get("warned") != tomorrow:
            set_cdata(pub, warned=tomorrow)
            c = find_client(pub)
            notify_admins("⏳ У клиента <b>%s</b> завтра (%s) истекает срок действия." % (
                e(c["name"]) if c else pub[:8], tomorrow))


# ====================== бэкап и обновление ======================
REPO = "s1riller/amnezia-server-kit"
INSTALLER_URL = "https://github.com/%s/releases/latest/download/install-vpn-kit.sh" % REPO
UPDATE_SENTINEL = os.path.join(DATA_DIR, "updated-to")   # версия, о которой нужно сообщить после перезапуска
# что кладём в бэкап (пути относительно /, только существующие)
BACKUP_PATHS = ["etc/vpn-bot", "etc/vpn-kit", "var/lib/vpn-bot", "opt/adguardhome/conf", "root/adguard-admin.txt"]


def kit_option(key, default=""):
    try:
        with open(KIT_OPTIONS, encoding="utf-8") as f:
            for line in f:
                if line.split("=", 1)[0] == key and "=" in line:
                    return line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return default


def backup_passphrase():
    """Пароль шифрования бэкапа: генерируем один раз и храним, чтобы последующие бэкапы шли тем же паролем."""
    p = CFG.get("backup_pass")
    new = not p
    if new:
        import secrets
        p = secrets.token_urlsafe(18)
        CFG["backup_pass"] = p
        save_cfg()
    return p, new


def set_backup_pass(value):
    """Задать свой пароль бэкапа (или сгенерировать, если value пуст). -> новый пароль."""
    import secrets
    CFG["backup_pass"] = (value or "").strip() or secrets.token_urlsafe(18)
    save_cfg()
    return CFG["backup_pass"]


def view_bpass():
    p = CFG.get("backup_pass")
    if p:
        text = ("🔑 <b>Пароль шифрования бэкапа</b>\n\n"
                "Текущий пароль (нажмите, чтобы увидеть):\n<tg-spoiler><code>%s</code></tg-spoiler>\n\n"
                "Им открываются зашифрованные бэкапы. Сохраните его отдельно: если потеряете "
                "и сервер, и пароль одновременно — старый бэкап восстановить будет нельзя." % e(p))
    else:
        text = ("🔑 <b>Пароль шифрования бэкапа</b>\n\n"
                "Пароль ещё не создан — он появится при первом бэкапе (💾 Бэкап в Telegram) и будет показан.")
    kb = [[btn("🔁 Новый случайный", "bpgen"), btn("✏️ Задать свой", "bpset")],
          [btn("⬅️ Сервис", "service")]]
    return text, kb


def make_backup():
    """-> (имя_файла, зашифрованные_байты, пароль, пароль_новый). Шифрование openssl AES-256 + PBKDF2.
    Пароль передаётся openssl через окружение (env:), а данные tar — через pipe."""
    paths = [p for p in BACKUP_PATHS if os.path.exists("/" + p)]
    if not paths:
        raise RuntimeError("нечего сохранять")
    pw, new = backup_passphrase()
    env = dict(os.environ, VPNKIT_BACKUP_PW=pw)
    tar = subprocess.Popen(["tar", "czf", "-", "-C", "/"] + paths,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    enc = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", "env:VPNKIT_BACKUP_PW"],
                         stdin=tar.stdout, capture_output=True, env=env)
    tar.stdout.close()
    tar.wait()
    if tar.returncode not in (0, None) or enc.returncode != 0:
        raise RuntimeError("tar/openssl: " + (enc.stderr.decode(errors="replace")[:200] or "ошибка"))
    return "vpn-kit-backup-%s.tar.gz.enc" % time.strftime("%Y%m%d-%H%M%S"), enc.stdout, pw, new


def do_backup(chat):
    send(chat, "⏳ Готовлю зашифрованный бэкап…")
    try:
        fname, data, pw, new = make_backup()
    except Exception as ex:
        log("backup:", traceback.format_exc())
        send(chat, "❌ Не удалось сделать бэкап: %s" % e(str(ex)), [BACK])
        return
    cap = ("💾 Зашифрованный бэкап (клиенты, ключи, настройки AdGuard и бота).\n"
           "Восстановление на новом сервере:\n"
           "<code>bash install-vpn-kit.sh --restore %s</code>") % fname
    send_file(chat, fname, data, cap, "application/octet-stream")
    if new:
        send(chat, "🔑 <b>Пароль для восстановления</b> (сохраните — показывается один раз):\n"
                   "<code>%s</code>\n\nБез него восстановить бэкап нельзя." % e(pw))
    else:
        send(chat, "Пароль для восстановления — тот же, что был показан при первом бэкапе.")


def ver_tuple(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or "0"))


def latest_release():
    """Тег последнего релиза на GitHub без 'v'. Ошибка сети -> исключение."""
    req = urllib.request.Request("https://api.github.com/repos/%s/releases/latest" % REPO,
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "vpn-kit"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return (json.loads(r.read()).get("tag_name") or "").lstrip("v")


def check_update():
    """Записать CFG['update_available'] = тег, если на GitHub версия новее установленной. -> тег|None."""
    try:
        latest = latest_release()
    except Exception:
        return CFG.get("update_available")
    nv = latest if latest and ver_tuple(latest) > ver_tuple(kit_option("KIT_VERSION", "0")) else None
    if CFG.get("update_available") != nv:
        CFG["update_available"] = nv
        save_cfg()
    return nv


def http_bytes(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-kit"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def do_update(chat):
    import hashlib
    send(chat, "⏳ Скачиваю последнюю версию установщика…")
    try:
        script = http_bytes(INSTALLER_URL)
        want = http_bytes(INSTALLER_URL + ".sha256").decode().split()[0]
    except Exception as ex:
        send(chat, "❌ Не удалось скачать: %s" % e(str(ex)), [BACK])
        return
    got = hashlib.sha256(script).hexdigest()
    if got != want:
        send(chat, "❌ Контрольная сумма не совпала — обновление отменено.\nОжидалось %s, получено %s"
             % (want[:16], got[:16]), [BACK])
        return
    tmp = "/tmp/vpn-kit-update.sh"
    with open(tmp, "wb") as f:
        f.write(script)
    ver = CFG.get("update_available") or "?"
    with open(UPDATE_SENTINEL, "w", encoding="utf-8") as f:
        f.write(ver)
    send(chat, "✅ Контрольная сумма верна. Запускаю обновление до <b>%s</b>.\n"
               "Бот перезапустится, я пришлю подтверждение." % e(str(ver)))
    # отдельный транзиентный юнит, чтобы обновление пережило перезапуск самого бота
    rc, _, err = run(["systemd-run", "--unit=vpn-kit-update", "--collect", "bash", tmp])
    if rc != 0:
        os.remove(UPDATE_SENTINEL)
        send(chat, "❌ Не удалось запустить обновление: %s" % e(err.strip()), [BACK])


def delete_client(pub):
    with _awg_lock:
        conf = read_file(AWG_CONF)
        blocks = split_blocks(conf)
        keep = [b for b in blocks
                if not (block_name(b) == "Peer" and dict(block_items(b)).get("PublicKey") == pub)]
        if len(keep) == len(blocks):
            raise RuntimeError("клиент не найден в конфигурации")
        backup_awg()
        write_file(AWG_CONF, "".join(keep))
        dexec("awg", "set", AWG_IF, "peer", pub, "remove")
        save_table([c for c in load_table() if c.get("clientId") != pub])
        try:
            os.remove(conf_path(pub))
        except FileNotFoundError:
            pass
    if pub in CFG.get("blocked", []) or pub in CFG.get("share_mute", {}) or pub in CFG.get("clients", {}):
        CFG["blocked"] = [p for p in CFG.get("blocked", []) if p != pub]
        CFG.get("share_mute", {}).pop(pub, None)
        CFG.get("clients", {}).pop(pub, None)
        save_cfg()
    tr = load_traffic()
    if tr.pop(pub, None) is not None:
        save_traffic(tr)
        write_blocked_file()


def qr_png(text):
    try:
        p = subprocess.run(["qrencode", "-t", "PNG", "-o", "-", "-s", "5", "-m", "2", "-l", "L"],
                           input=text.encode(), capture_output=True, timeout=20)
        return p.stdout if p.returncode == 0 and p.stdout else None
    except Exception:
        return None


# ====================== система ======================
_cstate_cache = {}   # name -> (ts, (running, started))


def container_state(name):
    c = _cstate_cache.get(name)
    if c and time.time() - c[0] < 2.5:
        return c[1]
    rc, out, _ = run(["docker", "inspect", "-f", "{{.State.Running}}|{{.State.StartedAt}}", name])
    st = (False, "absent") if rc != 0 else (out.strip().split("|", 1)[0] == "true", out.strip().split("|", 1)[1])
    _cstate_cache[name] = (time.time(), st)
    return st


_cpu_prev = None


def cpu_percent():
    """Загрузка CPU без блокировки: дельта между этим и предыдущим вызовом (sleep только при самом первом)."""
    global _cpu_prev

    def snap():
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        return v[3] + v[4], sum(v)
    idle, total = snap()
    if _cpu_prev is None:
        _cpu_prev = (idle, total)
        time.sleep(0.08)
        idle, total = snap()
    i0, t0 = _cpu_prev
    _cpu_prev = (idle, total)
    dt = total - t0
    return 100.0 * (1 - (idle - i0) / dt) if dt > 0 else 0.0


def meminfo():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            m[k] = int(v.split()[0]) * 1024
    return m["MemTotal"], m["MemAvailable"]


def wan_iface():
    _, out, _ = run(["ip", "-4", "route", "show", "default"])
    m = re.search(r"\bdev (\S+)", out)
    return m.group(1) if m else None


def f2b_banned():
    rc, out, _ = run(["fail2ban-client", "status", "sshd"], timeout=10)
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return int(m.group(1)) if rc == 0 and m else None


def ru_ipset_count():
    rc, out, _ = run(["ipset", "list", "ru_v4", "-t"])
    m = re.search(r"Number of entries:\s*(\d+)", out)
    return int(m.group(1)) if rc == 0 and m else None


def ru_rejected():
    _, out, _ = run(["iptables", "-L", "DOCKER-USER", "-v", "-n", "-x"])
    for line in out.splitlines():
        if "match-set ru_v4" in line:
            return int(line.split()[0])
    return None


# ====================== AdGuard ======================
def ag_creds():
    d = {}
    try:
        with open(ADGUARD_CRED, encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    d[k.strip()] = v.strip()
    except FileNotFoundError:   # AdGuard не установлен (--no-adguard)
        pass
    return d.get("Login", "admin"), d.get("Password", "")


def ag(method, path, data=None):
    user, pw = ag_creds()
    req = urllib.request.Request(
        "http://%s%s" % (ADGUARD_IP, path), method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read()
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def ag_user_rules():
    return ag("GET", "/control/filtering/status").get("user_rules") or []


def ru_dns_enabled():
    try:
        rules = ag_user_rules()
        return all(r in rules for r in RU_DNS_RULES)
    except Exception:
        return None


def set_ru_dns(enable):
    rules = [r for r in ag_user_rules() if r not in RU_DNS_RULES and r != RU_DNS_COMMENT]
    if enable:
        rules += [RU_DNS_COMMENT] + RU_DNS_RULES
    ag("POST", "/control/filtering/set_rules", {"rules": rules})


# ---------- файл раздельного туннелирования для приложения AmneziaVPN ----------
SPLIT_LOCAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4"]
SPLIT_KEEP_IN_VPN = ["172.29.172.0/24"]   # внутренняя сеть сервера (AdGuard) — должна идти через VPN

SPLIT_HOWTO = (
    "📲 <b>Российские сайты без VPN — настройка AmneziaVPN</b>\n\n"
    "1. Обновите AmneziaVPN до последней версии.\n"
    "2. Сохраните файл <code>ip-list.json</code> из этого чата на устройство.\n"
    "3. Настройки → Раздельное туннелирование → <b>Сайты</b>.\n"
    "4. Режим: <b>«Адреса из списка не должны открываться через VPN»</b>.\n"
    "5. ⋮ (три точки) → Импорт → <b>«Заменить список с сайтами»</b> → выберите файл.\n"
    "6. Включите раздельное туннелирование и переподключитесь к VPN.\n\n"
    "На Android дополнительно: Раздельное туннелирование → <b>Приложения</b> → добавьте банки, "
    "Госуслуги, Яндекс, VK, маркетплейсы — они будут работать без VPN.\n\n"
    "Список обновляется редко; если какой-то российский сайт перестал открываться — попросите новый файл.")


def split_file():
    import ipaddress as ia
    nets = []
    if os.path.exists(RU_CACHE):
        with open(RU_CACHE) as f:
            nets = [ia.ip_network(l.strip()) for l in f if l.strip()]
    if not nets:
        raise RuntimeError("список российских сетей пуст — обновите его в разделе «Блокировка RU»")
    for n in SPLIT_LOCAL:
        n = ia.ip_network(n)
        parts = [n]
        for keep in map(ia.ip_network, SPLIT_KEEP_IN_VPN):
            parts = [q for p in parts for q in (p.address_exclude(keep) if keep.subnet_of(p) else [p])]
        nets += parts
    nets = list(ia.collapse_addresses(nets))
    data = json.dumps([{"hostname": str(n), "ip": ""} for n in nets], ensure_ascii=False, indent=1)
    return data.encode(), len(nets)


# ---------- AdGuard: настройки по клиентам ----------
def ag_sync():
    """VPN-клиенты -> «Клиенты» AdGuard, затем правила (детский режим -> запрет DoT)"""
    run([SYNC_SCRIPT], timeout=60)


def ag_client_by_ip(ip):
    for c in ag("GET", "/control/clients").get("clients") or []:
        if ip in (c.get("ids") or []):
            return c
    return None


def ag_is_kids(c):
    return bool(c and not c.get("use_global_settings") and c.get("parental_enabled")
                and ((c.get("safe_search") or {}).get("enabled") or c.get("safesearch_enabled")))


def ag_mode(c):
    if not c:
        return "нет в AdGuard"
    if c.get("use_global_settings"):
        return "обычный"
    if ag_is_kids(c):
        return "👶 детский"
    if not c.get("filtering_enabled"):
        return "без фильтрации"
    return "особые настройки (заданы в веб-панели)"


def ag_set_kids(ip, on):
    c = ag_client_by_ip(ip)
    if not c:
        ag_sync()
        c = ag_client_by_ip(ip)
    if not c:
        raise RuntimeError("клиент %s не найден в AdGuard" % ip)
    data = dict(c)
    data.pop("safesearch_enabled", None)       # устаревшее поле, актуальное — safe_search
    if on:
        data.update(use_global_settings=False, filtering_enabled=True, parental_enabled=True,
                    safebrowsing_enabled=True, safe_search=dict(SAFESEARCH_ALL, enabled=True))
    else:
        data.update(use_global_settings=True, filtering_enabled=True, parental_enabled=False,
                    safebrowsing_enabled=False, safe_search=dict(SAFESEARCH_ALL, enabled=False))
    ag("POST", "/control/clients/update", {"name": c["name"], "data": data})
    ag_sync()                                  # обновит список детского режима
    run([VPN_NET_SCRIPT], timeout=60)          # и сразу применит запрет DoT


def ag_client_queries(ip, limit=25):
    d = ag("GET", "/control/querylog?search=%s&limit=300" % ip)
    res, seen = [], set()
    for it in d.get("data") or []:
        if it.get("client") != ip:
            continue
        dom = ((it.get("question") or {}).get("name") or "?").rstrip(".")
        blocked = (it.get("reason") or "").startswith("Filtered")
        if (dom, blocked) in seen:
            continue
        seen.add((dom, blocked))
        res.append((it.get("time", "")[11:16], dom, blocked))
        if len(res) >= limit:
            break
    return res


def ag_top_clients():
    s = ag("GET", "/control/stats")
    return [(k, v) for d in (s.get("top_clients") or []) for k, v in d.items()]


# ====================== экраны ======================
def btn(t, d):
    return {"text": t, "callback_data": d}


BACK = [btn("⬅️ Меню", "menu")]
MAIN_KB = [[btn("📊 Статус", "status"), btn("👥 Клиенты", "clients")],
           [btn("➕ Новый клиент", "add"), btn("🛡 AdGuard", "adguard")],
           [btn("🇷🇺 Блокировка RU", "ru"), btn("💳 Оплата", "pay")],
           [btn("⚙️ Сервис", "service")]]


def view_menu():
    kb = [row[:] for row in MAIN_KB]
    n = len(CFG.get("requests", {}))
    if n:
        kb = [[btn("📨 Заявки на доступ (%d)" % n, "reqs")]] + kb
    return "<b>🛡 Панель VPN-сервера</b>\nВыберите раздел:", kb


def ok_icon(b):
    return "🟢" if b else "🔴"


def build_report():
    """Короткая сводка для админов: сервер, клиенты, трафик за месяц, AdGuard."""
    total, avail = meminfo()
    disk = shutil.disk_usage("/")
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    lines = ["<b>📈 Ежедневный отчёт</b> · %s" % today_str(),
             "⏱ Аптайм %s · 💾 RAM %.0f%% · 💿 Диск %.0f%%" % (
                 dur(uptime), 100.0 * (total - avail) / total, 100.0 * disk.used / disk.total)]
    try:
        cl = get_clients()
        online = sum(1 for c in cl if c["hs"] and time.time() - c["hs"] < ONLINE_SEC)
        blocked = sum(1 for c in cl if is_blocked(c["pub"]))
        lines.append("👥 Клиентов: %d (онлайн %d, отключены %d)" % (len(cl), online, blocked))
        tr = load_traffic()
        top = sorted(cl, key=lambda c: used_bytes(c["pub"], tr), reverse=True)
        top = [c for c in top if used_bytes(c["pub"], tr) > 0][:5]
        if top:
            lines.append("\n<b>Трафик за месяц (топ):</b>")
            for c in top:
                cd = cdata(c["pub"])
                lim = " / %d ГБ" % cd["limit_gb"] if cd.get("limit_gb") else ""
                lines.append("  • %s — %s%s" % (e(c["name"]), hb(used_bytes(c["pub"], tr)), lim))
        soon = [c for c in cl if cdata(c["pub"]).get("expires")
                and cdata(c["pub"])["expires"] <= time.strftime("%Y-%m-%d", time.localtime(time.time() + 3 * 86400))]
        if soon:
            lines.append("\n<b>⏳ Скоро истекает срок:</b>")
            for c in soon:
                lines.append("  • %s — до %s" % (e(c["name"]), cdata(c["pub"])["expires"]))
    except Exception as ex:
        lines.append("👥 Клиенты: ошибка (%s)" % e(str(ex)))
    try:
        s = ag("GET", "/control/stats")
        q, bl = s.get("num_dns_queries", 0), s.get("num_blocked_filtering", 0)
        lines.append("\n🛡 AdGuard за 7 дней: запросов %d, заблокировано %d (%.0f%%)" % (
            q, bl, 100.0 * bl / q if q else 0))
    except Exception:
        pass
    return "\n".join(lines)


def view_status():
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    with open("/proc/loadavg") as f:
        load = " ".join(f.read().split()[:3])
    total, avail = meminfo()
    disk = shutil.disk_usage("/")
    wan = wan_iface()
    rx = tx = 0
    if wan:
        with open("/sys/class/net/%s/statistics/rx_bytes" % wan) as f:
            rx = int(f.read())
        with open("/sys/class/net/%s/statistics/tx_bytes" % wan) as f:
            tx = int(f.read())
    _, host, _ = run(["hostname"])
    _, cc, _ = run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"])
    awg_run = container_state(AWG_CONTAINER)[0]
    ag_run = container_state(ADGUARD_CONTAINER)[0]
    lines = ["<b>📊 Сервер</b> <code>%s</code>" % e(host.strip()),
             "⏱ Аптайм: %s" % dur(uptime),
             "🧠 CPU: %.0f%% · нагрузка %s" % (cpu_percent(), load),
             "💾 RAM: %s из %s (%.0f%%)" % (hb(total - avail), hb(total), 100.0 * (total - avail) / total),
             "💿 Диск: %s из %s (%.0f%%)" % (hb(disk.used), hb(disk.total), 100.0 * disk.used / disk.total),
             "🌐 Трафик с момента загрузки: ⬇️ %s ⬆️ %s" % (hb(rx), hb(tx)),
             "", "<b>🔐 VPN</b>",
             "%s AmneziaWG" % ok_icon(awg_run)]
    if awg_run:
        try:
            cl = get_clients()
            online = sum(1 for c in cl if c["hs"] and time.time() - c["hs"] < ONLINE_SEC)
            lines.append("👥 Клиентов: %d, онлайн: %d" % (len(cl), online))
        except Exception as ex:
            lines.append("👥 Клиенты: ошибка (%s)" % e(str(ex)))
    lines.append("%s AdGuard Home (DNS)" % ok_icon(ag_run))
    n = ru_ipset_count()
    lines.append("%s Блокировка RU по IP%s" % (ok_icon(n), (": %d сетей" % n) if n else " выключена"))
    lines.append("⚡️ TCP: %s" % e(cc.strip()))
    b = f2b_banned()
    if b is not None:
        lines.append("🚫 fail2ban: заблокировано IP — %d" % b)
    if os.path.exists("/var/run/reboot-required"):
        lines.append("\n⚠️ После обновлений нужна перезагрузка — выполнится автоматически в 04:00")
    return "\n".join(lines), [[btn("🩺 Проверка доступности", "vpncheck"), btn("🔄 Обновить", "status")], BACK]


def view_vpncheck():
    if not container_state(AWG_CONTAINER)[0]:
        return "<b>🩺 Проверка доступности VPN</b>\n🔴 Контейнер AmneziaWG не запущен.", \
               [[btn("🔄 Ещё раз", "vpncheck")], BACK]
    eg = server_egress_ok()
    cl = get_clients()
    now = time.time()
    online = sum(1 for c in cl if c["hs"] and now - c["hs"] < ONLINE_SEC)
    active = sum(1 for c in cl if c["hs"] and now - c["hs"] < BLOCK_HS_RECENT)
    lines = ["<b>🩺 Проверка доступности VPN</b>",
             "%s Выход сервера в интернет" % ok_icon(eg),
             "👥 Клиентов: %d · онлайн: %d · активны за 5 мин: %d" % (len(cl), online, active)]
    if not eg:
        lines.append("\n🔴 Сам сервер не выходит в интернет — это проблема сервера/хостера, "
                     "а не блокировка у провайдера клиента.")
    elif len(cl) > 0 and active == 0:
        lines.append("\n⚠️ Сервер исправен и в сети, но активных клиентов нет. Если пользователи "
                     "жалуются — возможна блокировка провайдером (режут IP или порт).")
    else:
        lines.append("\n🟢 Сервер исправен, выходит в интернет, клиенты подключаются.")
    return "\n".join(lines), [[btn("🔬 Анализ трафика (DPI)", "traffic"), btn("🔄 Ещё раз", "vpncheck")], BACK]


# ---------- анализатор «зашифрованности» трафика (взгляд DPI) ----------
HI_ENTROPY = 7.5          # байт/байт: выше — «похоже на шифр/случайность»


def byte_entropy(data):
    """Энтропия Шеннона полезной нагрузки, 0..8 бит/байт."""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def classify_header(p):
    """Грубая классификация первых байт полезной нагрузки."""
    if len(p) >= 4 and p[0] in (1, 2, 3, 4) and p[1] == 0 and p[2] == 0 and p[3] == 0:
        return "wg"       # ванильный заголовок WireGuard (тип 1..4 + нулевые reserved)
    if len(p) >= 3 and p[0] == 0x16 and p[1] == 0x03:
        return "tls"      # TLS-запись
    if len(p) >= 1 and (p[0] & 0xC0) == 0xC0:
        return "quic"     # QUIC long header (грубо)
    return "other"


def awg_listen_port():
    try:
        _, iface, _ = awg_conf()
        p = dict(iface).get("ListenPort", "")
        return int(p) if str(p).isdigit() else 0
    except Exception:
        return 0


def capture_awg_udp(port, seconds=6, max_pkts=600):
    """Сырой захват UDP-пакетов на порту AmneziaWG (AF_PACKET, нужен root/Linux).
    -> list[payload_bytes]. Анализируем нагрузку так, как её видит наблюдатель в сети."""
    wan = wan_iface()
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except (AttributeError, PermissionError, OSError) as ex:
        raise RuntimeError("захват недоступен (нужен root/Linux): %s" % ex)
    out = []
    try:
        if wan:
            s.bind((wan, 0))
        s.settimeout(1.0)
        end = time.time() + seconds
        while time.time() < end and len(out) < max_pkts:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 14:
                continue
            eth = struct.unpack("!H", frame[12:14])[0]
            off = 14
            if eth == 0x8100 and len(frame) >= 18:      # VLAN-метка
                eth = struct.unpack("!H", frame[16:18])[0]
                off = 18
            if eth != 0x0800:                            # только IPv4
                continue
            ip = frame[off:]
            if len(ip) < 20 or ip[9] != 17:              # только UDP
                continue
            ihl = (ip[0] & 0x0F) * 4
            udp = ip[ihl:]
            if len(udp) < 8:
                continue
            sport, dport = struct.unpack("!HH", udp[:4])
            if port not in (sport, dport):
                continue
            out.append(udp[8:])
    finally:
        s.close()
    return out


def view_traffic():
    port = awg_listen_port()
    if not port:
        return "<b>🔬 Анализ трафика</b>\n🔴 Не удалось определить порт AmneziaWG.", [[btn("⬅️ Назад", "status")]]
    try:
        pkts = capture_awg_udp(port)
    except Exception as ex:
        return "<b>🔬 Анализ трафика</b>\n🔴 %s" % e(str(ex)), [[btn("🔄 Ещё раз", "traffic")], BACK]
    kb = [[btn("🔄 Ещё раз", "traffic")], BACK]
    if not pkts:
        return ("<b>🔬 Анализ трафика VPN</b>\nЗа 6 c на порту %d пакетов не поймано. "
                "Нужен активный клиент (попросите кого-то пользоваться VPN в момент анализа)." % port, kb)
    ent = [byte_entropy(p) for p in pkts if p]
    sizes = [len(p) for p in pkts]
    hdr = collections.Counter(classify_header(p) for p in pkts)
    mean_ent = sum(ent) / len(ent) if ent else 0.0
    hi = sum(1 for h in ent if h >= HI_ENTROPY)
    hi_pct = 100.0 * hi / len(ent) if ent else 0
    small = sum(1 for z in sizes if z < 120)
    mid = sum(1 for z in sizes if 120 <= z <= 300)
    big = sum(1 for z in sizes if z > 1000)
    uniq = len(set(sizes))
    lines = ["<b>🔬 Анализ трафика VPN</b> (взгляд наблюдателя в сети)",
             "Порт AmneziaWG: %d · поймано пакетов: %d за ~6 c" % (port, len(pkts)),
             "Средняя энтропия: %.2f бит/байт (шифр ≈ 8.0)" % mean_ent,
             "Высокоэнтропийных (≥%.1f): %.0f%%" % (HI_ENTROPY, hi_pct),
             "Размеры: мелкие&lt;120: %d · 120–300: %d · &gt;1000: %d · разных размеров: %d" % (small, mid, big, uniq),
             "Заголовки: WG-ванильный %d · TLS %d · QUIC %d · прочее %d"
             % (hdr["wg"], hdr["tls"], hdr["quic"], hdr["other"])]
    # вердикт: важна НЕ высокая энтропия (она ожидаема у шифра), а отпечаток
    if hdr["wg"]:
        lines.append("\n🔴 В %d пакетах — <b>ванильный заголовок WireGuard</b>. Обфускация не маскирует "
                     "тип сообщения, такой трафик DPI распознаёт. Проверьте H1–H4 в настройках сервера "
                     "(приложение Amnezia) и перевыпустите конфиги." % hdr["wg"])
    elif mean_ent >= 7.8 and hi_pct >= 90 and uniq <= 3:
        lines.append("\n🟠 Трафик — почти однородный высокоэнтропийный UDP без узнаваемого рукопожатия и "
                     "с малой вариативностью размеров. Для DPI это типичный признак VPN. Помогает добавление "
                     "мусорных пакетов и разброса размеров (Jc/Jmin/Jmax, S1/S2 в AmneziaWG).")
    else:
        lines.append("\n🟢 Ванильного WG-заголовка нет, есть вариативность — трафик выделяется слабее. "
                     "Высокая энтропия сама по себе нормальна (данные шифрованы); DPI ловит именно "
                     "фиксированные заголовки/размеры, а их здесь не видно.")
    lines.append("\n<i>Оценка приблизительная: на коротких пакетах энтропия шумит, сжатые данные похожи "
                 "на шифрованные. Анализируется только трафик вашего сервера.</i>")
    return "\n".join(lines), kb


# ---------- смена маскировки (магические заголовки H1–H4 AmneziaWG) ----------
def _set_conf_param(text, key, val):
    """Заменить значение параметра key в тексте конфига (строки `key = …`)."""
    return re.sub(r"(?mi)^(\s*%s\s*=\s*).*$" % re.escape(key), lambda m: m.group(1) + str(val), text)


def obfs_headers():
    """Текущие H1–H4 из [Interface] сервера."""
    try:
        _, iface, _ = awg_conf()
    except Exception:
        return {}
    d = dict(iface)
    return {k: d[k] for k in ("H1", "H2", "H3", "H4") if k in d}


def gen_headers():
    """Четыре различных случайных значения ≥5 (1–4 заняты типами WireGuard)."""
    import secrets
    vals = set()
    while len(vals) < 4:
        vals.add(5 + secrets.randbelow(2_000_000_000))
    v = list(vals)
    return {"H1": str(v[0]), "H2": str(v[1]), "H3": str(v[2]), "H4": str(v[3])}


def set_obfs_headers(newvals):
    """Сменить H1–H4 на сервере с бэкапом, перезапуском и автооткатом. -> (ok, сообщение)."""
    with _awg_lock:
        old = read_file(AWG_CONF)
        if not all(k in old for k in ("H1", "H2", "H3", "H4")):
            return False, "в конфиге нет H1–H4 (эта версия AmneziaWG их не использует)"
        backup_awg()
        conf = old
        for k, val in newvals.items():
            conf = _set_conf_param(conf, k, val)
        write_file(AWG_CONF, conf)
    run(["docker", "restart", AWG_CONTAINER], timeout=120)
    container_pid_reset()
    time.sleep(4)
    up = container_state(AWG_CONTAINER)[0]
    rc = dexec("awg", "show", AWG_IF)[0] if up else 1
    egress = server_egress_ok() if up else False
    if not (up and rc == 0 and egress):
        with _awg_lock:
            write_file(AWG_CONF, old)                    # автооткат
        run(["docker", "restart", AWG_CONTAINER], timeout=120)
        container_pid_reset()
        time.sleep(3)
        run([VPN_NET_SCRIPT], timeout=60)
        return False, "VPN не поднялся с новыми параметрами (up=%s awg=%s egress=%s) — выполнен откат" % (up, rc == 0, egress)
    run([VPN_NET_SCRIPT], timeout=60)
    enforce_blocked()
    return True, "ok"


def reissue_after_rotation(newvals):
    """Переписать H1–H4 в сохранённых конфигах клиентов и разослать владельцам. -> (отправлено, без_кабинета, из_приложения)."""
    reissued, unowned, appmade = [], [], 0
    for c in get_clients():
        pub = c["pub"]
        if not c["has_conf"]:
            appmade += 1
            continue
        try:
            with open(conf_path(pub), encoding="utf-8") as f:
                text = f.read()
        except OSError:
            continue
        for k, val in newvals.items():
            text = _set_conf_param(text, k, val)
        save_client_conf(pub, text)
        owner = cdata(pub).get("owner")
        if owner:
            send(owner, "🔄 Параметры VPN обновлены — вот новая конфигурация. Старая больше не подключится.")
            send_client_conf(owner, c["name"], c["ip"], text)
            reissued.append(c["name"])
        else:
            unowned.append(c["name"])
    return reissued, unowned, appmade


def do_rotate_obfs(chat):
    send(chat, "⏳ Меняю маскировку (H1–H4) и перезапускаю VPN (~10 c, клиенты переподключатся)…")
    newvals = gen_headers()
    try:
        ok, msg = set_obfs_headers(newvals)
    except Exception as ex:
        log("rotate_obfs:", traceback.format_exc())
        send(chat, "❌ Ошибка при смене маскировки: %s. Параметры могли не измениться — проверьте 📊 Статус." % e(str(ex)),
             [[btn("⬅️ Назад", "obfs")]])
        return
    if not ok:
        send(chat, "❌ Не удалось: %s. Клиенты не затронуты." % e(msg), [[btn("⬅️ Назад", "obfs")]])
        return
    reissued, unowned, appmade = reissue_after_rotation(newvals)
    txt = ["✅ Маскировка обновлена, VPN поднялся. Новые заголовки: <code>%s</code>"
           % e(" ".join("%s=%s" % (k, newvals[k]) for k in ("H1", "H2", "H3", "H4"))),
           "Перевыпущено и отправлено клиентам с кабинетом: %d" % len(reissued)]
    if unowned:
        txt.append("Без кабинета — раздайте конфиг вручную (карточка клиента → «Конфиг + QR»): %d" % len(unowned))
    if appmade:
        txt.append("Созданы в приложении Amnezia — переимпортируйте из приложения: %d" % appmade)
    send(chat, "\n".join(txt), [[btn("⬅️ Назад", "obfs")]])


def view_obfs():
    h = obfs_headers()
    if not h:
        return ("<b>🕵️ Маскировка</b>\n\nВ конфиге сервера нет H1–H4 — эта версия AmneziaWG их не "
                "использует, менять нечего.", [[btn("⬅️ Сервис", "service")]])
    vanilla = all(h.get(k) == str(i) for i, k in enumerate(("H1", "H2", "H3", "H4"), 1))
    lines = ["<b>🕵️ Маскировка трафика</b> (заголовки AmneziaWG H1–H4)",
             "Текущие: <code>%s</code>" % e(" ".join("%s=%s" % (k, h[k]) for k in ("H1", "H2", "H3", "H4") if k in h))]
    if vanilla:
        lines.append("\n🔴 Заголовки = 1,2,3,4 — как у ванильного WireGuard, который DPI распознаёт. "
                     "Рекомендую сменить.")
    lines.append("\nСмена даёт серверу уникальную подпись и ломает сигнатуры DPI.\n"
                 "⚠️ VPN перезапустится (~10 c), и всем клиентам нужен новый конфиг — "
                 "бот перевышлет тем, у кого есть кабинет; остальных нужно раздать вручную.")
    auto = CFG.get("auto_rotate")
    lines.append("\n🤖 Автосмена при подозрении на блок: <b>%s</b>." % ("включена" if auto else "выключена"))
    if auto:
        lines.append("Если сервер исправен, но все активные клиенты разом отвалились, бот сам сменит "
                     "маскировку (не чаще раза в 6 ч). Это серверная эвристика, не канарейка — возможны "
                     "ложные срабатывания и лишние переподключения. Включайте после проверки кнопки вручную.")
    kb = [[btn("🎲 Сменить маскировку", "obfsrot")],
          [btn("🤖 Автосмена: ВКЛ (выключить)" if auto else "🤖 Автосмена: выкл (включить)", "obfsauto")],
          [btn("⬅️ Сервис", "service")]]
    return "\n".join(lines), kb


# ---------- XRay (VLESS + Reality) — запасной протокол против DPI ----------
XRAY_CONTAINER = "xray"
XRAY_DIR = "/etc/xray"
XRAY_CONF = XRAY_DIR + "/config.json"
XRAY_IMAGE = "teddysun/xray"
XRAY_SNI_DEFAULT = "www.microsoft.com"


def xray_cfg():
    return CFG.setdefault("xray", {})


def xray_installed():
    return bool(xray_cfg().get("privkey"))


def xray_sni():
    return (xray_cfg().get("sni") or "").strip() or XRAY_SNI_DEFAULT


def xray_gen_keys():
    """Пара ключей Reality через `xray x25519`. -> (private, public)."""
    rc, out, err = run(["docker", "run", "--rm", XRAY_IMAGE, "xray", "x25519"], timeout=120)
    if rc != 0:
        raise RuntimeError("xray x25519: " + (err.strip() or out.strip())[:200])
    vals = re.findall(r":\s*([A-Za-z0-9_-]{43,44})", out)
    if len(vals) < 2:
        raise RuntimeError("не удалось разобрать ключи x25519")
    return vals[0], vals[1]


def xray_write_config():
    """Собрать config.json из настроек и UUID клиентов, записать на хост (смонтирован в контейнер)."""
    c = xray_cfg()
    clients = [{"id": cdata(pub).get("xray_uuid"), "flow": "xtls-rprx-vision"}
               for pub in CFG.get("clients", {}) if cdata(pub).get("xray_uuid")]
    conf = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "0.0.0.0", "port": c.get("port", 443), "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "dest": xray_sni() + ":443", "serverNames": [xray_sni()],
                "privateKey": c.get("privkey", ""), "shortIds": [c.get("sid", "")]}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}],
        "outbounds": [{"protocol": "freedom"}],
    }
    os.makedirs(XRAY_DIR, exist_ok=True)
    tmp = XRAY_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2, ensure_ascii=False)
    os.replace(tmp, XRAY_CONF)


def xray_restart():
    run(["docker", "restart", XRAY_CONTAINER], timeout=60)


def install_xray():
    """Поднять контейнер XRay с Reality. -> (ok, сообщение)."""
    rc, _, err = run(["docker", "pull", "-q", XRAY_IMAGE], timeout=300)
    if rc != 0:
        return False, "не удалось скачать образ XRay: " + err.strip()[:200]
    c = xray_cfg()
    if not c.get("privkey"):
        import secrets
        priv, pub = xray_gen_keys()
        c.update(privkey=priv, pubkey=pub, sid=secrets.token_hex(4), port=443)
        c.setdefault("sni", XRAY_SNI_DEFAULT)
        save_cfg()
    xray_write_config()
    run(["docker", "rm", "-f", XRAY_CONTAINER], timeout=60)
    rc, _, err = run(["docker", "run", "-d", "--name", XRAY_CONTAINER, "--restart", "unless-stopped",
                      "-p", "%d:%d" % (c.get("port", 443), c.get("port", 443)),
                      "-v", XRAY_DIR + ":/etc/xray", XRAY_IMAGE], timeout=120)
    if rc != 0:
        return False, "не удалось запустить контейнер: " + err.strip()[:200]
    run(["ufw", "allow", "%d/tcp" % c.get("port", 443)], timeout=30)
    time.sleep(2)
    if not container_state(XRAY_CONTAINER)[0]:
        rc2, logs, _ = run(["docker", "logs", "--tail", "15", XRAY_CONTAINER], timeout=20)
        return False, "контейнер не запустился:\n" + e(logs.strip()[-400:])
    return True, "ok"


def vless_url(pub):
    c = xray_cfg()
    uid = cdata(pub).get("xray_uuid")
    cl = find_client(pub)
    name = urllib.parse.quote((cl["name"] if cl else "xray")[:40])
    return ("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality"
            "&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s"
            % (uid, server_ip(), c.get("port", 443), urllib.parse.quote(xray_sni()),
               c.get("pubkey", ""), c.get("sid", ""), name))


def give_xray(chat, pub):
    c = find_client(pub)
    if not cdata(pub).get("xray_uuid"):
        set_cdata(pub, xray_uuid=str(uuid.uuid4()))
        xray_write_config()
        xray_restart()
    url = vless_url(pub)
    send(chat, "🧅 <b>XRay (VLESS Reality)</b> для <b>%s</b> — запасной вход, если AmneziaWG заблокируют.\n"
               "Импортируйте в v2rayNG / NekoBox / Hiddify по ссылке или QR:\n<code>%s</code>" % (e(c["name"] if c else "?"), e(url)))
    png = qr_png(url)
    if png:
        send_photo(chat, png, "QR XRay для «%s»" % e(c["name"] if c else "?"))


def remove_xray(pub):
    if cdata(pub).get("xray_uuid"):
        set_cdata(pub, xray_uuid=None)
        xray_write_config()
        xray_restart()


def view_xray():
    c = xray_cfg()
    if not xray_installed():
        return ("<b>🧅 XRay (VLESS + Reality)</b>\n\nЗапасной протокол, стойкий к DPI: когда AmneziaWG "
                "режут, клиент переключается на него. Слушает порт 443, маскируется под обычный HTTPS-сайт.\n\n"
                "⚠️ Займёт порт 443 и ресурсы. После установки выдавайте клиентам кнопкой в их карточке.",
                [[btn("⬇️ Установить XRay", "xrinstall")], [btn("⬅️ Сервис", "service")]])
    running = container_state(XRAY_CONTAINER)[0]
    n = sum(1 for pub in CFG.get("clients", {}) if cdata(pub).get("xray_uuid"))
    lines = ["<b>🧅 XRay (VLESS + Reality)</b>",
             "%s Контейнер: %s" % (ok_icon(running), "работает" if running else "не запущен"),
             "Маскировка (SNI): <b>%s</b>" % e(xray_sni()),
             "Порт: %d · клиентов с XRay: %d" % (c.get("port", 443), n),
             "\nВыдавайте XRay клиентам в их карточке («🧅 Дать XRay»)."]
    kb = [[btn("✏️ Сайт маскировки (SNI)", "xrsni"), btn("🔁 Перезапустить", "xrrestart")],
          [btn("♻️ Переустановить", "xrinstall"), btn("🗑 Удалить XRay", "xrremove")],
          [btn("⬅️ Сервис", "service")]]
    return "\n".join(lines), kb


# ---------- канарейка: установка на хост в РФ ----------
CANARY_NAME = "canary"
# ставим канарейку из ветки main (не зависит от канала релиза — работает и с предрелизом)
CANARY_INSTALLER = "https://raw.githubusercontent.com/%s/main/canary/install-canary.sh" % REPO


def canary_conf_b64():
    """Конфиг канареечного клиента (создаётся при необходимости) в base64."""
    c = next((c for c in get_clients() if c["name"] == CANARY_NAME and c["has_conf"]), None)
    if c:
        with open(conf_path(c["pub"]), encoding="utf-8") as f:
            text = f.read()
    else:
        r = create_client(CANARY_NAME)
        ag_sync()
        text = r["conf"]
    return base64.b64encode(text.encode()).decode()


def canary_install_cmd(admin_chat):
    """Готовая команда для запуска на Linux-хосте в России."""
    label = re.sub(r"[^\w .-]", "", srv_name())[:30] or "canary"
    return ("curl -fsSL %s | bash -s -- --token %s --chat %s --label '%s' --conf-b64 %s"
            % (CANARY_INSTALLER, CFG.get("token", ""), admin_chat, label, canary_conf_b64()))


def view_canary():
    text = ("<b>🩺 Канарейка</b>\n\n"
            "Проверяет доступность VPN из сети пользователя (нужен отдельный Linux-хост "
            "<b>в России</b>) и шлёт тревогу при блокировке.\n\n"
            "• <b>Команда установки</b> — пришлю строку, вставьте её на хосте (от root). "
            "Скрипт поставит канарейку и защитит хост (ufw, fail2ban, автообновления, BBR).\n"
            "• <b>Установить по SSH</b> — бот сам зайдёт и поставит (нужны логин и пароль хоста).\n\n"
            "⚠️ В обоих случаях токен бота окажется на хосте канарейки.")
    kb = [[btn("📋 Команда установки", "caninstall")],
          [btn("🔐 Установить по SSH", "canssh")],
          BACK]
    return text, kb


def do_canary_ssh(chat, line):
    parts = line.split()
    if len(parts) < 2 or "@" not in parts[0]:
        send(chat, "Формат: <code>root@IP[:порт] пароль [метка]</code>. /cancel — отмена")
        return
    dest, password = parts[0], parts[1]
    label = re.sub(r"[^\w .-]", "", " ".join(parts[2:]))[:30] or "canary"
    user_host, _, port = dest.partition(":")
    port = port or "22"
    if not shutil.which("sshpass") or not shutil.which("ssh"):
        send(chat, "На сервере нет <code>sshpass</code>/<code>ssh</code>. Обновите набор "
                   "(⚙️ Сервис → «Обновить набор») — он их поставит — и повторите.", [[btn("⬅️ Канарейка", "canary")]])
        return
    send(chat, "⏳ Подключаюсь к <code>%s</code> и ставлю канарейку. Это может занять несколько минут…" % e(user_host))
    try:
        b64 = canary_conf_b64()
    except Exception as ex:
        send(chat, "❌ Не удалось подготовить конфиг канарейки: %s" % e(str(ex)), [[btn("⬅️ Канарейка", "canary")]])
        return
    remote = ("curl -fsSL %s | bash -s -- --token %s --chat %s --label '%s' --conf-b64 %s"
              % (CANARY_INSTALLER, CFG.get("token", ""), chat, label, b64))
    env = dict(os.environ, SSHPASS=password)
    rc, out, err = run(["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=accept-new",
                        "-o", "ConnectTimeout=20", "-p", port, user_host, remote], env=env, timeout=600)
    tail = e((out + err).strip()[-1200:] or "нет вывода")
    if rc == 0:
        send(chat, "✅ Канарейка установлена на <code>%s</code>.\n\n<pre>%s</pre>" % (e(user_host), tail),
             [[btn("⬅️ Канарейка", "canary")]])
    else:
        hint = "неверные логин/пароль/хост или нет SSH" if rc in (5, 255) else "см. вывод"
        send(chat, "❌ Не удалось (код %d, %s):\n\n<pre>%s</pre>" % (rc, hint, tail),
             [[btn("⬅️ Канарейка", "canary")]])


client_filter = {}   # chat -> (поисковый запрос, режим)
CLIENT_MODES = ["all", "online", "off", "soon"]
MODE_LABEL = {"all": "все", "online": "онлайн", "off": "отключённые", "soon": "истекает ≤3д"}


def get_filter(chat):
    return client_filter.get(chat, ("", "all"))


def set_filter(chat, q=None, mode=None):
    oq, om = get_filter(chat)
    nq = oq if q is None else q
    nm = om if mode is None else mode
    if not nq and nm == "all":
        client_filter.pop(chat, None)
    else:
        client_filter[chat] = (nq, nm)


def client_matches(c, q, mode, now, soon_date):
    if q and q.lower() not in c["name"].lower() and q not in c["ip"]:
        return False
    if mode == "online":
        return bool(c["hs"]) and now - c["hs"] < ONLINE_SEC
    if mode == "off":
        return is_blocked(c["pub"])
    if mode == "soon":
        exp = cdata(c["pub"]).get("expires")
        return bool(exp) and exp <= soon_date
    return True


def view_clients(chat=None):
    q, mode = get_filter(chat)
    now = time.time()
    soon_date = time.strftime("%Y-%m-%d", time.localtime(now + 3 * 86400))
    allcl = get_clients()
    cl = [c for c in allcl if client_matches(c, q, mode, now, soon_date)]
    lines = ["<b>👥 Клиенты</b> — показано %d из %d" % (len(cl), len(allcl))]
    filt = ([("поиск: «%s»" % e(q)) if q else ""] if q else []) + \
           ([("фильтр: %s" % MODE_LABEL[mode])] if mode != "all" else [])
    if filt:
        lines.append("  " + " · ".join(x for x in filt if x))
    lines += ["🟢 онлайн · ⚪️ нет 3 мин · ⛔ отключён", ""]
    kb = []
    shown = 0
    for c in cl:
        online = c["hs"] and now - c["hs"] < ONLINE_SEC
        dot = "⛔" if is_blocked(c["pub"]) else "🟢" if online else "⚪️"
        if sum(len(x) for x in lines) < 3300:
            lines.append("%s <b>%s</b> · %s · %s · ⬇️%s ⬆️%s" % (
                dot, e(c["name"]), c["ip"], ago(c["hs"]), hb(c["tx"]), hb(c["rx"])))
        if shown < 60:
            kb.append([btn("%s %s" % (dot, c["name"][:40]), "c:" + c["pub"])])
            shown += 1
    if len(cl) > 60:
        lines.append("\n…показаны первые 60 кнопок. Уточните поиск или фильтр.")
    if not cl:
        lines.append("Ничего не найдено." if (q or mode != "all") else "Клиентов пока нет.")
    ctl = [btn("🔍 Поиск", "csearch"), btn("Фильтр: %s" % MODE_LABEL[mode], "clmode")]
    if q or mode != "all":
        ctl.append(btn("✖ Сброс", "clrfilt"))
    kb.append(ctl)
    kb.append([btn("➕ Новый клиент", "add"), btn("🔄 Обновить", "clients")])
    kb.append(BACK)
    return "\n".join(lines), kb


def find_client(pub):
    for c in get_clients():
        if c["pub"] == pub:
            return c
    return None


def view_client(pub):
    c = find_client(pub)
    if not c:
        return "Клиент не найден (возможно, уже удалён).", [[btn("⬅️ К списку", "clients")]]
    ep = c["endpoint"]
    blocked = is_blocked(pub)
    cd = cdata(pub)
    off = cd.get("auto_off")
    status = {"expired": "  ⛔ <b>СРОК ИСТЁК</b>", "limit": "  ⛔ <b>ЛИМИТ ИСЧЕРПАН</b>"}.get(
        off, "  ⛔ <b>ОТКЛЮЧЁН</b>" if blocked else "")
    used = used_bytes(pub)
    lim = cd.get("limit_gb")
    if lim:
        left = max(0, lim * GB - used)
        traf = "Трафик за месяц: %s из %d ГБ (осталось %s)" % (hb(used), lim, hb(left))
    else:
        traf = "Трафик за месяц: %s (лимит не задан)" % hb(used)
    exp = cd.get("expires")
    srok = ("Срок действия: до %s%s" % (exp, " ⚠️" if is_expired(cd) else "")) if exp else "Срок действия: бессрочно"
    lines = ["<b>👤 %s</b>%s" % (e(c["name"]), status),
             "IP в VPN: <code>%s</code>" % c["ip"],
             "Создан: %s" % e(c["created"] or "—"),
             "Последнее подключение: %s" % ago(c["hs"]),
             "Откуда: <code>%s</code>" % e(ep.rsplit(":", 1)[0]) if ep and ep != "(none)" else "Откуда: —",
             traf, srok,
             "Ключ: <code>%s</code>" % e(c["pub"])]
    kb = []
    try:
        agc = ag_client_by_ip(c["ip"])
        q7 = dict(ag_top_clients()).get(c["ip"], 0)
        lines += ["", "<b>🛡 AdGuard</b>: режим — %s" % ag_mode(agc),
                  "DNS-запросов за 7 дней: %d" % q7]
        kids = ag_is_kids(agc)
        kb.append([btn("🔍 Запросы", "cq:" + pub),
                   btn("👶 Выключить детский режим" if kids else "👶 Детский режим", "ckids:" + pub)])
    except Exception as ex:
        lines.append("\n🛡 AdGuard недоступен: %s" % e(str(ex)))
    if not c["has_conf"]:
        lines.append("\n<i>Конфиг этого клиента создан в приложении Amnezia — у бота его нет.</i>")
    if c["has_conf"]:
        kb.append([btn("📄 Конфиг + QR", "cconf:" + pub)])
    kb.append([btn("⏳ Срок", "cexp:" + pub), btn("📊 Лимит", "clim:" + pub)])
    if off == "expired":
        kb.append([btn("➕ Продлить 30 дней", "cext:" + pub)])
    if off == "limit":
        kb.append([btn("♻️ Сбросить лимит", "clrst:" + pub)])
    if xray_installed():
        if cd.get("xray_uuid"):
            kb.append([btn("🧅 XRay-ссылка", "cxray:" + pub), btn("🧅 Убрать XRay", "cxroff:" + pub)])
        else:
            kb.append([btn("🧅 Дать XRay (запасной вход)", "cxray:" + pub)])
    kb.append([btn("🔑 Новый ключ", "crk:" + pub),
               btn("✅ Включить" if blocked else "⛔ Отключить", ("cunb:" if blocked else "cblk:") + pub)])
    kb.append([btn("🗑 Удалить", "cdel:" + pub)])
    kb.append([btn("⬅️ К списку", "clients"), btn("🔄", "c:" + pub)])
    return "\n".join(lines), kb


def view_adguard():
    _, pw = ag_creds()
    lines = ["<b>🛡 AdGuard Home</b>"]
    kb = []
    try:
        st = ag("GET", "/control/status")
        s = ag("GET", "/control/stats")
        q, bl = s.get("num_dns_queries", 0), s.get("num_blocked_filtering", 0)
        prot = st.get("protection_enabled")
        lines += ["%s Защита: %s · версия %s" % (ok_icon(prot), "включена" if prot else "ВЫКЛЮЧЕНА",
                                                   e(st.get("version", "?"))),
                  "Запросов за 7 дней: %d" % q,
                  "Заблокировано: %d (%.1f%%)" % (bl, 100.0 * bl / q if q else 0),
                  "Среднее время ответа: %.0f мс" % (1000 * (s.get("avg_processing_time") or 0))]
        top = s.get("top_blocked_domains") or []
        if top:
            lines.append("\nЧаще всего блокируется:")
            for d in top[:5]:
                for dom, cnt in d.items():
                    lines.append("  • %s — %d" % (e(dom), cnt))
        tc = [(k, v) for d in (s.get("top_clients") or []) for k, v in d.items()]
        if tc:
            names = {c["ip"]: c["name"] for c in get_clients()}
            lines.append("\nАктивнее всего (DNS-запросы):")
            for ip, cnt in tc[:5]:
                lines.append("  • %s — %d" % (e(names.get(ip, ip)), cnt))
        kb.append([btn("⏸ Выключить защиту" if prot else "▶️ Включить защиту",
                       "agoff" if prot else "agon")])
    except Exception as ex:
        lines.append("🔴 AdGuard недоступен: %s" % e(str(ex)))
    lines += ["", "Веб-панель (открывается только при включённом VPN):",
              "http://%s" % ADGUARD_IP, "Логин: <code>admin</code>",
              "Пароль: <tg-spoiler><code>%s</code></tg-spoiler>" % e(pw)]
    kb.append([btn("🔄 Перезапустить AdGuard", "ask:rag"), btn("🔄", "adguard")])
    kb.append(BACK)
    return "\n".join(lines), kb


def view_ru():
    n = ru_ipset_count()
    rej = ru_rejected()
    _, en, _ = run(["systemctl", "is-enabled", "block-ru.timer"])
    ip_on = n is not None
    dns_on = ru_dns_enabled()
    upd = "—"
    if os.path.exists(RU_CACHE):
        upd = time.strftime("%d.%m.%Y %H:%M", time.localtime(os.path.getmtime(RU_CACHE)))
    lines = ["<b>🇷🇺 Блокировка российских ресурсов</b>", "",
             "%s По IP-адресам: %s" % (ok_icon(ip_on), ("%d сетей" % n) if ip_on else "выключена"),
             "   Список обновлён: %s (автообновление: %s)" % (upd, "еженедельно" if en.strip() == "enabled" else "выкл"),
             "   Отклонено соединений: %s" % (rej if rej is not None else "—"),
             "%s По доменам .ru / .рф / .su (DNS): %s" % (
                 ok_icon(dns_on), "включена" if dns_on else ("выключена" if dns_on is False else "AdGuard недоступен"))]
    if dns_on:
        lines.append("\n⚠️ Если пользователи включат раздельное туннелирование (российские сайты без VPN), "
                     "блок доменов нужно выключить: DNS идёт через VPN, и домены .ru не будут открываться.")
    kb = [[btn("📲 Файл «российские сайты без VPN»", "rusplit")],
          [btn("🔄 Обновить список IP", "ruupd")],
          [btn("Выключить блок по IP" if ip_on else "Включить блок по IP", "ruipoff" if ip_on else "ruipon")],
          [btn("Выключить блок доменов" if dns_on else "Включить блок доменов", "rudnsoff" if dns_on else "rudnson")],
          BACK]
    return "\n".join(lines), kb


REPORT_LABELS = {"daily": "ежедневно", "weekly": "еженедельно (пн)", "off": "выключен"}


def view_service():
    mode = CFG.get("report", "daily")
    ver = kit_option("KIT_VERSION", "?")
    nv = CFG.get("update_available")
    text = ("<b>⚙️ Сервис</b>\n\n"
            "Версия набора: <b>%s</b>%s\n"
            "Имя сервера (для AmneziaVPN): <b>%s</b>\n"
            "Ежедневный отчёт: <b>%s</b>\n\n"
            "• Перезапуск VPN — клиенты переподключатся автоматически (~10 сек).\n"
            "• Перезагрузка сервера — VPN недоступен ~1 мин." % (
                e(str(ver)), ("\n⬆️ Доступна версия <b>%s</b>" % e(str(nv)) if nv else ""),
                e(srv_name()), REPORT_LABELS[mode]))
    kb = [[btn("✏️ Имя сервера", "srvname")],
          [btn("💾 Бэкап в Telegram", "backup"), btn("🔑 Пароль бэкапа", "bpass")],
          [btn("🩺 Канарейка", "canary"), btn("🕵️ Маскировка", "obfs")],
          [btn("🧅 XRay (запасной протокол)", "xray")],
          [btn("⬆️ Обновить набор" if nv else "⬆️ Проверить обновления", "update")],
          [btn("📈 Отчёт: %s" % REPORT_LABELS[mode], "reptgl")],
          [btn("🔄 Перезапустить VPN", "ask:rvpn")],
          [btn("🔄 Перезапустить AdGuard", "ask:rag")],
          [btn("♻️ Перезагрузить сервер", "ask:reboot")],
          BACK]
    return text, kb


CONFIRM = {"rvpn": "Перезапустить контейнер VPN?",
           "rag": "Перезапустить AdGuard Home?",
           "reboot": "Перезагрузить сервер? VPN будет недоступен около минуты."}


# ====================== заявки на доступ и кабинет пользователя ======================
REQ_REALERT = 3600   # не чаще раза в час напоминать админам об одной и той же заявке


def client_owned_by(uid):
    for c in get_clients():
        if cdata(c["pub"]).get("owner") == uid:
            return c
    return None


def add_request(uid, name, username):
    reqs = CFG.setdefault("requests", {})
    r = reqs.get(str(uid))
    now = int(time.time())
    if r and now - r.get("ts", 0) < REQ_REALERT:
        return False   # уже есть свежая заявка — не спамим админов
    reqs[str(uid)] = {"name": name, "username": username, "ts": now}
    save_cfg()
    return True


def notify_request(uid):
    r = CFG.get("requests", {}).get(str(uid), {})
    who = e(r.get("name") or "без имени")
    un = (" (@%s)" % e(r["username"])) if r.get("username") else ""
    txt = "📨 <b>Заявка на доступ к VPN</b>\nОт: %s%s\nID: <code>%s</code>" % (who, un, uid)
    kb = [[btn("✅ Одобрить", "ap:%s" % uid), btn("🚫 Отклонить", "rej:%s" % uid)]]
    for a in ADMINS:
        send(a, txt, kb)


def view_reqs():
    reqs = CFG.get("requests", {})
    if not reqs:
        return "📨 <b>Заявки на доступ</b>\n\nНовых заявок нет.", [BACK]
    lines = ["📨 <b>Заявки на доступ (%d)</b>" % len(reqs), ""]
    kb = []
    for uid, r in sorted(reqs.items(), key=lambda kv: kv[1].get("ts", 0)):
        un = (" @%s" % r["username"]) if r.get("username") else ""
        lines.append("• %s%s — <code>%s</code>" % (e(r.get("name") or "без имени"), e(un), uid))
        kb.append([btn("✅ %s" % (r.get("name") or uid)[:30], "ap:%s" % uid),
                   btn("🚫", "rej:%s" % uid)])
    kb.append(BACK)
    return "\n".join(lines), kb


APPROVE_TERMS = [("♾ Бессрочно", 0), ("30 дней", 30), ("90 дней", 90)]
APPROVE_LIMITS = [("∞ Без лимита", 0), ("50 ГБ", 50), ("100 ГБ", 100)]


def do_approve(uid, days, gb):
    """Создать клиента по заявке, привязать к пользователю, выдать конфиг ему в личку."""
    r = CFG.get("requests", {}).get(str(uid), {})
    name = (r.get("name") or ("user%s" % uid)).strip()[:40]
    res = create_client(name)
    pub, ip = res["pub"], res["ip"]
    kw = {"owner": uid}
    if days:
        kw["expires"] = time.strftime("%Y-%m-%d", time.localtime(time.time() + days * 86400))
    if gb:
        kw["limit_gb"] = gb
    set_cdata(pub, **kw)
    CFG.get("requests", {}).pop(str(uid), None)
    save_cfg()
    ag_sync()
    # выдаём конфиг самому пользователю
    send(uid, "✅ Вам одобрен доступ к VPN. Ниже — конфигурация для подключения.")
    send_client_conf(uid, name, ip, res["conf"], created=False)
    send(uid, *view_cabinet(uid))
    return name, ip


def view_cabinet(uid):
    c = client_owned_by(uid)
    if not c:
        kb = []
        if tariffs_enabled():
            kb.append([btn("💳 Купить доступ", "buy")])
        pending_req = str(uid) in CFG.get("requests", {})
        if pending_req:
            kb.append([btn("🔄 Обновить", "my")])
            return ("⏳ Ваша заявка на доступ к VPN отправлена администратору. "
                    "Как только её одобрят, я пришлю конфигурацию сюда." +
                    ("\n\nИли оформите доступ сразу — кнопкой ниже." if tariffs_enabled() else ""),
                    kb or None)
        kb.append([btn("📨 Запросить доступ (бесплатно)", "req")])
        return ("👋 Здравствуйте! Этот бот выдаёт доступ к VPN. Выберите вариант ниже.", kb)
    pub = c["pub"]
    cd = cdata(pub)
    blocked = is_blocked(pub)
    off = cd.get("auto_off")
    used = used_bytes(pub)
    lim = cd.get("limit_gb")
    lines = ["<b>👤 Ваш VPN</b>"]
    if off == "expired" or (not blocked and cd.get("expires") and is_expired(cd)):
        lines.append("⛔ Срок действия истёк. Обратитесь к администратору.")
    elif off == "limit":
        lines.append("⛔ Исчерпан месячный лимит трафика. Возобновится в начале месяца.")
    elif blocked:
        lines.append("⛔ Доступ временно отключён администратором.")
    else:
        lines.append("🟢 Активен.")
    if cd.get("expires"):
        lines.append("Действует до: <b>%s</b>" % cd["expires"])
    else:
        lines.append("Срок: бессрочно")
    if lim:
        lines.append("Трафик за месяц: %s из %d ГБ (осталось %s)" % (hb(used), lim, hb(max(0, lim * GB - used))))
    else:
        lines.append("Трафик за месяц: %s" % hb(used))
    kb = []
    if c["has_conf"]:
        kb.append([btn("📄 Моя конфигурация + QR", "myconf")])
    if tariffs_enabled():
        kb.append([btn("💳 Купить / продлить", "buy")])
    kb.append([btn("🔄 Обновить", "my")])
    return "\n".join(lines), kb


# ====================== оплата Telegram Stars ======================
# Тариф: {"id","label","stars","days","gb"} — даёт days суток доступа и месячный лимит gb ГБ (0 = безлимит).
DEFAULT_TARIFFS = [
    {"id": "m1", "label": "30 дней · безлимит", "stars": 100, "days": 30, "gb": 0, "on": True},
    {"id": "m3", "label": "90 дней · безлимит", "stars": 250, "days": 90, "gb": 0, "on": True},
    {"id": "m1g", "label": "30 дней · 100 ГБ/мес", "stars": 60, "days": 30, "gb": 100, "on": True},
]
MAX_PAYMENTS_LOG = 200


def tariffs():
    if "tariffs" not in CFG:
        CFG["tariffs"] = [dict(t) for t in DEFAULT_TARIFFS]
        save_cfg()
    return CFG["tariffs"]


def tariff_by_id(tid):
    return next((t for t in tariffs() if t.get("id") == tid), None)


def tariffs_enabled():
    return any(t.get("on", True) for t in tariffs())


def send_invoice(chat, t):
    """Выставить счёт в Telegram Stars (XTR). provider_token для звёзд не нужен."""
    desc = "Доступ к VPN: %d дн." % t["days"] + ((" , до %d ГБ/мес" % t["gb"]) if t["gb"] else " , без лимита")
    r = tg("sendInvoice", {
        "chat_id": chat, "title": t["label"], "description": desc,
        "payload": "buy:%s" % t["id"], "currency": "XTR",
        "prices": [{"label": t["label"], "amount": int(t["stars"])}]})
    if not r.get("ok"):
        log("sendInvoice failed:", r.get("description"))
        send(chat, "❌ Не удалось выставить счёт: %s" % e(r.get("description", "ошибка")))
    return r


def apply_purchase(uid, t, charge_id=None, stars=None):
    """Выдать/продлить доступ после успешной оплаты (самообслуживание, без одобрения)."""
    c = client_owned_by(uid)
    created = False
    if not c:
        name = CFG.get("requests", {}).get(str(uid), {}).get("name") or ("user%s" % uid)
        res = create_client(name.strip()[:40])
        set_cdata(res["pub"], owner=uid)
        CFG.get("requests", {}).pop(str(uid), None)
        save_cfg()
        ag_sync()
        c = find_client(res["pub"])
        conf = res["conf"]
        created = True
    pub = c["pub"]
    cd = cdata(pub)
    kw = {}
    if t["days"]:
        base = max(today_str(), cd.get("expires") or today_str())
        bt = time.mktime(time.strptime(base, "%Y-%m-%d"))
        kw["expires"] = time.strftime("%Y-%m-%d", time.localtime(bt + t["days"] * 86400))
    kw["limit_gb"] = t["gb"] or None
    kw["auto_off"] = None
    kw["warned"] = None
    set_cdata(pub, **kw)
    tr = load_traffic()                       # оплаченный план — чистый счётчик трафика
    if tr.pop(pub, None) is not None:
        save_traffic(tr)
    if is_blocked(pub):
        set_blocked(pub, False)
    # лог платежа
    pay = CFG.setdefault("payments", [])
    pay.append({"uid": uid, "tariff": t["id"], "stars": stars or t["stars"],
                "charge_id": charge_id, "ts": int(time.time())})
    del pay[:-MAX_PAYMENTS_LOG]
    save_cfg()
    # уведомления
    exp = cdata(pub).get("expires")
    msg = "✅ Оплата получена. Доступ активен%s." % ((" до %s" % exp) if exp else "")
    if created:
        send(uid, msg + " Ниже — ваша конфигурация.")
        send_client_conf(uid, c["name"], c["ip"], conf, created=False)
    else:
        send(uid, msg)
    send(uid, *view_cabinet(uid))
    notify_admins("💳 Оплата %s⭐ от <b>%s</b> (ID %s): тариф «%s». Доступ выдан%s." % (
        stars or t["stars"], e(c["name"]), uid, e(t["label"]), (" до %s" % exp) if exp else ""))


def view_buy(uid):
    ts = [t for t in tariffs() if t.get("on", True)]
    if not ts:
        return "💳 Оплата временно недоступна.", [[btn("⬅️ Назад", "my")]]
    lines = ["💳 <b>Купить доступ к VPN</b>", "Оплата звёздами Telegram. Выберите тариф:"]
    kb = [[btn("%s — %d⭐" % (t["label"], t["stars"]), "buytar:%s" % t["id"])] for t in ts]
    c = client_owned_by(uid)
    kb.append([btn("⬅️ Назад", "my" if c else "umenu")])
    return "\n".join(lines), kb


# ---------- админ: тарифы и платежи ----------
def view_pay_admin():
    ts = tariffs()
    pays = CFG.get("payments", [])
    income = sum(p.get("stars", 0) for p in pays if not p.get("refunded"))
    lines = ["💳 <b>Оплата звёздами</b>",
             "Тарифов: %d · платежей: %d · получено: %d⭐" % (len(ts), len(pays), income), ""]
    kb = []
    for t in ts:
        mark = "✅" if t.get("on", True) else "🚫"
        kb.append([btn("%s %s — %d⭐" % (mark, t["label"], t["stars"]), "tedit:%s" % t["id"])])
    kb.append([btn("➕ Добавить тариф", "tadd"), btn("🧾 Платежи", "pays")])
    kb.append(BACK)
    return "\n".join(lines), kb


def view_tariff(tid):
    t = tariff_by_id(tid)
    if not t:
        return "Тариф не найден.", [[btn("⬅️ Оплата", "pay")]]
    lines = ["💳 <b>Тариф</b>", "Название: <b>%s</b>" % e(t["label"]),
             "Цена: <b>%d⭐</b>" % t["stars"],
             "Срок: <b>%d дн.</b>" % t["days"],
             "Лимит: <b>%s</b>" % (("%d ГБ/мес" % t["gb"]) if t["gb"] else "без лимита"),
             "Показывается пользователям: <b>%s</b>" % ("да" if t.get("on", True) else "нет")]
    kb = [[btn("💲 Цена", "tset:%s:stars" % tid), btn("📅 Срок", "tset:%s:days" % tid)],
          [btn("📊 ГБ/мес", "tset:%s:gb" % tid), btn("✏️ Название", "tset:%s:label" % tid)],
          [btn("🚫 Скрыть" if t.get("on", True) else "✅ Показать", "ttog:%s" % tid),
           btn("🗑 Удалить", "tdel:%s" % tid)],
          [btn("⬅️ Оплата", "pay")]]
    return "\n".join(lines), kb


def do_tariff_set(chat, tid, field, text):
    t = tariff_by_id(tid)
    if not t:
        send(chat, "Тариф не найден."); return
    text = text.strip()
    if field == "label":
        t["label"] = re.sub(r"\s+", " ", text)[:40]
    else:
        if not re.fullmatch(r"\d{1,6}", text):
            send(chat, "Нужно целое число. Попробуйте ещё раз или /cancel."); return
        v = int(text)
        if field == "stars" and not (1 <= v <= 10000):
            send(chat, "Цена в звёздах — от 1 до 10000."); return
        t[field] = v
    save_cfg()
    send(chat, "✅ Сохранено.")
    send(chat, *view_tariff(tid))


def view_payments():
    pays = CFG.get("payments", [])
    if not pays:
        return "🧾 Платежей пока нет.", [[btn("⬅️ Оплата", "pay")]]
    lines = ["🧾 <b>Последние платежи</b>", ""]
    kb = []
    for i in range(len(pays) - 1, max(-1, len(pays) - 11), -1):
        p = pays[i]
        when = time.strftime("%d.%m %H:%M", time.localtime(p.get("ts", 0)))
        ref = " · возврат" if p.get("refunded") else ""
        lines.append("%s — %d⭐ · ID %s · %s%s" % (when, p.get("stars", 0), p.get("uid"),
                                                   e(p.get("tariff", "")), ref))
        if not p.get("refunded") and p.get("charge_id"):
            kb.append([btn("↩️ Возврат %d⭐ (ID %s)" % (p.get("stars", 0), p.get("uid")), "ref:%d" % i)])
    kb.append([btn("⬅️ Оплата", "pay")])
    return "\n".join(lines), kb


def do_refund(i):
    pays = CFG.get("payments", [])
    if not (0 <= i < len(pays)):
        return "Платёж не найден."
    p = pays[i]
    if p.get("refunded"):
        return "Этот платёж уже возвращён."
    r = tg("refundStarPayment", {"user_id": p["uid"], "telegram_payment_charge_id": p["charge_id"]})
    if r.get("ok"):
        p["refunded"] = True
        save_cfg()
        try:
            send(p["uid"], "↩️ Вам возвращены %d⭐ за VPN. Доступ может быть ограничен администратором." % p.get("stars", 0))
        except Exception:
            pass
        return "✅ Возврат %d⭐ выполнен (ID %s). Доступ не отзывается автоматически — при необходимости отключите клиента вручную." % (p.get("stars", 0), p["uid"])
    return "❌ Возврат не удался: %s" % (r.get("description") or "ошибка")


# ====================== действия ======================
pending = {}   # chat_id -> "add_name"


def do_add(chat, name):
    name = re.sub(r"\s+", " ", name).strip()[:40]
    if not name:
        send(chat, "Имя не может быть пустым. Попробуйте ещё раз: ➕ Новый клиент")
        return
    send(chat, "⏳ Создаю клиента «%s»…" % e(name))
    try:
        r = create_client(name)
    except Exception as ex:
        log("create_client:", traceback.format_exc())
        send(chat, "❌ Не удалось создать клиента: %s" % e(str(ex)), [BACK])
        return
    ag_sync()
    send_client_conf(chat, name, r["ip"], r["conf"], created=True)
    send(chat, *view_menu())


def parse_date(s):
    """'ГГГГ-ММ-ДД', 'ДД.ММ.ГГГГ', 'ДД.ММ.ГГ' или '+N' (дней) -> 'ГГГГ-ММ-ДД'. Ошибка -> ValueError."""
    s = s.strip()
    if re.fullmatch(r"\+?\d{1,4}", s) and s.startswith("+"):
        return time.strftime("%Y-%m-%d", time.localtime(time.time() + int(s[1:]) * 86400))
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d.%m.%y"):
        try:
            return time.strftime("%Y-%m-%d", time.strptime(s, fmt))
        except ValueError:
            continue
    raise ValueError("не дата")


def do_set_limit(chat, kind, pub, text):
    c = find_client(pub)
    if not c:
        send(chat, "Клиент не найден (возможно, удалён).", [[btn("⬅️ К списку", "clients")]])
        return
    try:
        if kind == "exp":
            if text.strip() == "0":
                set_cdata(pub, expires=None, warned=None)
                msg = "✅ Срок действия снят — клиент бессрочный."
            else:
                d = parse_date(text)
                if d <= today_str():
                    send(chat, "Дата уже прошла. Отправьте будущую дату или /cancel."); return
                set_cdata(pub, expires=d, warned=None)
                msg = "✅ Срок действия: до <b>%s</b>." % d
        else:
            gb = int(re.sub(r"[^\d]", "", text) or "-1")
            if gb < 0:
                send(chat, "Нужно число гигабайт (например 50) или 0. /cancel — отмена."); return
            set_cdata(pub, limit_gb=gb or None)
            msg = "✅ Лимит снят." if gb == 0 else "✅ Месячный лимит: <b>%d ГБ</b>." % gb
    except ValueError:
        send(chat, "Не понял. Срок: <code>ГГГГ-ММ-ДД</code> или <code>+30</code>. "
                   "Лимит: число ГБ. <code>0</code> — снять. /cancel — отмена."); return
    # если ограничение сняли/ослабили и клиент был отключён автоматически — вернуть доступ
    cd = cdata(pub)
    if cd.get("auto_off") and not is_expired(cd) and not is_over_limit(cd, used_bytes(pub)):
        set_cdata(pub, auto_off=None)
        if is_blocked(pub):
            set_blocked(pub, False)
        msg += " Доступ восстановлен."
    send(chat, msg)
    send(chat, *view_client(pub))


def send_client_conf(chat, name, ip, conf, created=False):
    sn = srv_name()
    cap = ("✅ Клиент <b>%s</b> создан, IP %s\n\n" % (e(name), ip) if created else "📄 <b>%s</b>\n\n" % e(name)) + \
          ("Как подключиться: установите <b>AmneziaVPN</b> (или AmneziaWG) → «+» → "
           "«Файл с настройками» и выберите этот файл, либо отсканируйте QR-код ниже.")
    send_file(chat, conf_filename(name, ip), conf.encode(), cap)
    png = qr_png(conf)
    if png:
        send_photo(chat, png, "QR-код (AmneziaWG / ручной импорт) — «%s»" % e(name))
    # Ссылка/QR для AmneziaVPN: сервер отобразится под именем sn
    try:
        uri = build_vpn_uri(conf, sn)
        png2 = qr_png(uri)
        if png2:
            send_photo(chat, png2, "QR для AmneziaVPN — сервер «%s»" % e(sn))
        send(chat, "Ссылка для <b>AmneziaVPN</b> (сервер «%s») — скопировать и в приложении «+» → "
                   "«Ввести вручную»/«Вставить»:\n<code>%s</code>" % (e(sn), e(uri)))
    except Exception:
        log("vpn_uri:", traceback.format_exc())


def handle_callback(cq):
    uid = cq["from"]["id"]
    data = cq.get("data", "")
    msg = cq.get("message") or {}
    chat, mid = msg.get("chat", {}).get("id"), msg.get("message_id")
    tg("answerCallbackQuery", {"callback_query_id": cq["id"]})
    if chat is None:
        return

    def show(view):
        edit(chat, mid, *view)

    def wait(text):
        edit(chat, mid, "⏳ " + text)

    if uid not in ADMINS:
        # кабинет обычного пользователя — только свои кнопки
        try:
            if data == "req":
                if client_owned_by(uid):
                    show(view_cabinet(uid))
                else:
                    name = cq["from"].get("first_name") or cq["from"].get("username") or "без имени"
                    if add_request(uid, name, cq["from"].get("username")):
                        notify_request(uid)
                    show(("✅ Заявка отправлена администратору. Я пришлю конфигурацию, как только её одобрят.", None))
            elif data == "my":
                show(view_cabinet(uid))
            elif data == "umenu":
                show(view_cabinet(uid))
            elif data == "myconf":
                c = client_owned_by(uid)
                if c and os.path.exists(conf_path(c["pub"])):
                    with open(conf_path(c["pub"]), encoding="utf-8") as f:
                        send_client_conf(uid, c["name"], c["ip"], f.read())
                else:
                    send(uid, "Конфигурация недоступна, обратитесь к администратору.")
            elif data == "buy":
                show(view_buy(uid))
            elif data.startswith("buytar:"):
                t = tariff_by_id(data[7:])
                if not t or not t.get("on", True):
                    show(("Тариф недоступен.", [[btn("⬅️ Назад", "buy")]]))
                else:
                    send_invoice(chat, t)
        except Exception:
            log("user callback %s: %s" % (data, traceback.format_exc()))
        return

    try:
        if data == "menu":
            pending.pop(chat, None)
            show(view_menu())
        elif data == "status":
            show(view_status())
        elif data == "vpncheck":
            wait("Проверяю доступность…")
            show(view_vpncheck())
        elif data == "traffic":
            wait("Снимаю трафик ~6 секунд…")
            show(view_traffic())
        elif data == "clients":
            show(view_clients(chat))
        elif data == "csearch":
            pending[chat] = "csearch"
            show(("🔍 Отправьте имя или IP (часть) для поиска клиента. "
                  "Пустое сообщение не сбрасывает — используйте «✖ Сброс». /cancel — отмена",
                  [[btn("⬅️ К списку", "clients")]]))
        elif data == "clmode":
            _, m = get_filter(chat)
            set_filter(chat, mode=CLIENT_MODES[(CLIENT_MODES.index(m) + 1) % len(CLIENT_MODES)])
            show(view_clients(chat))
        elif data == "clrfilt":
            client_filter.pop(chat, None)
            show(view_clients(chat))
        elif data.startswith("c:"):
            show(view_client(data[2:]))
        elif data.startswith("cconf:"):
            pub = data[6:]
            c = find_client(pub)
            if c and os.path.exists(conf_path(pub)):
                with open(conf_path(pub), encoding="utf-8") as f:
                    send_client_conf(chat, c["name"], c["ip"], f.read())
            else:
                send(chat, "Конфиг не найден.")
        elif data.startswith("crk:"):
            pub = data[4:]
            c = find_client(pub)
            if not c:
                show(("Клиент не найден (возможно, ключ уже заменён).", [[btn("⬅️ К списку", "clients")]]))
            else:
                show(("🔑 Выдать клиенту <b>%s</b> новый ключ?\n\nТекущий конфиг перестанет работать на "
                      "<b>всех</b> устройствах, где он установлен. Бот пришлёт новый конфиг — отправьте его "
                      "только настоящему владельцу. Имя, IP и настройки AdGuard сохранятся." % e(c["name"]),
                      [[btn("✅ Да, новый ключ", "crkok:" + pub), btn("❌ Отмена", "c:" + pub)]]))
        elif data.startswith("crkok:"):
            pub = data[6:]
            c = find_client(pub)
            if not c:
                show(("Клиент не найден (возможно, ключ уже заменён).", [[btn("⬅️ К списку", "clients")]]))
            else:
                wait("Выпускаю новый ключ…")
                r = rekey_client(pub)
                send_client_conf(chat, c["name"], r["ip"], r["conf"])
                send(chat, "✅ Ключ клиента <b>%s</b> заменён. Старые копии конфига больше не работают." % e(c["name"]))
                send(chat, *view_client(r["pub"]))
        elif data.startswith("cblk:"):
            pub = data[5:]
            c = find_client(pub)
            show(("⛔ Отключить клиента <b>%s</b>?\nVPN перестанет работать на всех его устройствах, "
                  "пока вы не включите его обратно. Конфиг сохранится." % e(c["name"] if c else "?"),
                  [[btn("✅ Да, отключить", "cblkok:" + pub), btn("❌ Отмена", "c:" + pub)]]))
        elif data.startswith("cblkok:"):
            pub = data[7:]
            wait("Отключаю…")
            set_cdata(pub, auto_off=None)       # ручное отключение «берёт верх» над автоматикой
            set_blocked(pub, True)
            show(view_client(pub))
        elif data.startswith("cunb:"):
            pub = data[5:]
            wait("Включаю…")
            set_cdata(pub, auto_off=None, warned=None)
            set_blocked(pub, False)
            show(view_client(pub))
        elif data.startswith("cexp:"):      # задать срок действия (текстом)
            pub = data[5:]
            pending[chat] = "exp:" + pub
            c = find_client(pub)
            cur = cdata(pub).get("expires")
            show(("⏳ Срок действия для <b>%s</b>\n\nОтправьте дату в формате <code>ГГГГ-ММ-ДД</code> "
                  "или число дней (<code>+30</code>). Сейчас: %s\n<code>0</code> — сделать бессрочным. /cancel — отмена"
                  % (e(c["name"] if c else "?"), cur or "бессрочно"), [[btn("⬅️ Отмена", "c:" + pub)]]))
        elif data.startswith("clim:"):      # задать месячный лимит (текстом)
            pub = data[5:]
            pending[chat] = "lim:" + pub
            c = find_client(pub)
            cur = cdata(pub).get("limit_gb")
            show(("📊 Месячный лимит трафика для <b>%s</b>\n\nОтправьте число гигабайт (например <code>50</code>). "
                  "Сейчас: %s\n<code>0</code> — без лимита. /cancel — отмена"
                  % (e(c["name"] if c else "?"), ("%d ГБ" % cur) if cur else "без лимита"),
                  [[btn("⬅️ Отмена", "c:" + pub)]]))
        elif data.startswith("cext:"):      # продлить на 30 дней от сегодня/текущего срока
            pub = data[5:]
            wait("Продлеваю…")
            base = max(today_str(), cdata(pub).get("expires") or today_str())
            bt = time.strptime(base, "%Y-%m-%d")
            new = time.strftime("%Y-%m-%d", time.localtime(time.mktime(bt) + 30 * 86400))
            set_cdata(pub, expires=new, warned=None)
            send(chat, "✅ Срок продлён до <b>%s</b>." % new)
            show(view_client(pub))
        elif data.startswith("clrst:"):     # сбросить месячный лимит
            pub = data[6:]
            wait("Сбрасываю лимит…")
            tr = load_traffic()
            if tr.pop(pub, None) is not None:
                save_traffic(tr)
            set_cdata(pub, auto_off=None)
            if is_blocked(pub):
                set_blocked(pub, False)
            send(chat, "✅ Счётчик трафика за месяц сброшен, доступ восстановлен.")
            show(view_client(pub))
        elif data == "reqs":
            show(view_reqs())
        elif data.startswith("ap:"):        # одобрение заявки: шаг 1 — срок
            u = data[3:]
            if str(u) not in CFG.get("requests", {}):
                show(("Заявка уже обработана или отозвана.", [[btn("📨 Заявки", "reqs")], BACK]))
            else:
                r = CFG["requests"][str(u)]
                show(("✅ Одобрить <b>%s</b> (ID <code>%s</code>)\n\nШаг 1 — срок действия:" % (
                    e(r.get("name") or "без имени"), u),
                    [[btn(t, "apt:%s:%d" % (u, d))] for t, d in APPROVE_TERMS] +
                    [[btn("🚫 Отклонить", "rej:%s" % u), btn("⬅️ Заявки", "reqs")]]))
        elif data.startswith("apt:"):       # шаг 2 — лимит
            u, days = data[4:].split(":")
            show(("✅ Одобрение <b>ID %s</b>, срок: %s.\n\nШаг 2 — месячный лимит трафика:" % (
                u, dict((d, t) for t, d in APPROVE_TERMS).get(int(days), "?")),
                [[btn(t, "apl:%s:%s:%d" % (u, days, g))] for t, g in APPROVE_LIMITS] +
                [[btn("⬅️ Заявки", "reqs")]]))
        elif data.startswith("apl:"):       # создать клиента и выдать конфиг
            u, days, gb = data[4:].split(":")
            if str(u) not in CFG.get("requests", {}):
                show(("Заявка уже обработана.", [[btn("📨 Заявки", "reqs")], BACK]))
            else:
                wait("Создаю клиента и отправляю конфиг пользователю…")
                try:
                    name, ip = do_approve(int(u), int(days), int(gb))
                    send(chat, "✅ Клиент <b>%s</b> создан (IP %s) и конфиг отправлен пользователю." % (e(name), ip))
                except Exception as ex:
                    log("approve:", traceback.format_exc())
                    send(chat, "❌ Не удалось одобрить: %s" % e(str(ex)))
                show(view_reqs())
        elif data.startswith("rej:"):       # отклонить заявку
            u = data[4:]
            CFG.get("requests", {}).pop(str(u), None)
            save_cfg()
            try:
                send(int(u), "🚫 Ваша заявка на доступ к VPN отклонена.")
            except Exception:
                pass
            show(view_reqs())
        elif data == "pay":
            show(view_pay_admin())
        elif data.startswith("tedit:"):
            show(view_tariff(data[6:]))
        elif data.startswith("tset:"):
            _, tid, field = data.split(":")
            pending[chat] = "tset:%s:%s" % (tid, field)
            labels = {"stars": "цену в звёздах (1–10000)", "days": "срок в днях (0 — без срока)",
                      "gb": "месячный лимит в ГБ (0 — без лимита)", "label": "название тарифа"}
            show(("Отправьте %s. /cancel — отмена" % labels[field], [[btn("⬅️ Назад", "tedit:" + tid)]]))
        elif data.startswith("ttog:"):
            t = tariff_by_id(data[5:])
            if t:
                t["on"] = not t.get("on", True)
                save_cfg()
            show(view_tariff(data[5:]))
        elif data.startswith("tdel:"):
            tid = data[5:]
            CFG["tariffs"] = [t for t in tariffs() if t.get("id") != tid]
            save_cfg()
            show(view_pay_admin())
        elif data == "tadd":
            tid = "t%d" % int(time.time())
            tariffs().append({"id": tid, "label": "Новый тариф", "stars": 100, "days": 30, "gb": 0, "on": False})
            save_cfg()
            show(view_tariff(tid))
        elif data == "pays":
            show(view_payments())
        elif data.startswith("ref:"):
            show((do_refund(int(data[4:])), [[btn("🧾 Платежи", "pays"), btn("⬅️ Оплата", "pay")]]))
        elif data.startswith("shign:"):
            pub = data[6:]
            CFG.setdefault("share_mute", {})[pub] = int(time.time()) + SHARE_MUTE
            save_cfg()
            c = find_client(pub)
            show(("🔕 Уведомления о нескольких устройствах для <b>%s</b> отключены на сутки." % e(c["name"] if c else "?"),
                  [[btn("👤 Клиент", "c:" + pub)], BACK]))
        elif data.startswith("ckids:"):
            pub = data[6:]
            c = find_client(pub)
            if c:
                on = not ag_is_kids(ag_client_by_ip(c["ip"]))
                wait("Включаю детский режим…" if on else "Выключаю детский режим…")
                ag_set_kids(c["ip"], on)
                send(chat, ("👶 Детский режим для <b>%s</b> включён: фильтр сайтов для взрослых, "
                            "безопасный поиск Google/Яндекс/YouTube, защита от фишинга, запрет обхода "
                            "через «Частный DNS»." if on else "Детский режим для <b>%s</b> выключен.") % e(c["name"]))
            show(view_client(pub))
        elif data.startswith("cq:"):
            pub = data[3:]
            c = find_client(pub)
            if not c:
                show(("Клиент не найден.", [[btn("⬅️ К списку", "clients")]]))
            else:
                q = ag_client_queries(c["ip"])
                lines = ["<b>🔍 %s — последние DNS-запросы</b>" % e(c["name"]),
                         "⛔ заблокировано · журнал хранится 24 ч", ""]
                lines += ["%s %s %s" % (t, "⛔" if b else "▫️", e(dom)) for t, dom, b in q] or ["Запросов пока нет."]
                show(("\n".join(lines)[:4000], [[btn("🔄", "cq:" + pub), btn("⬅️ Назад", "c:" + pub)]]))
        elif data.startswith("cdel:"):
            pub = data[5:]
            c = find_client(pub)
            name = c["name"] if c else "?"
            show(("🗑 Удалить клиента <b>%s</b>?\nОн сразу потеряет доступ к VPN." % e(name),
                  [[btn("✅ Да, удалить", "cdelok:" + pub), btn("❌ Отмена", "c:" + pub)]]))
        elif data.startswith("cdelok:"):
            pub = data[7:]
            c = find_client(pub)
            had_xray = bool(cdata(pub).get("xray_uuid"))
            delete_client(pub)
            ag_sync()
            if had_xray and xray_installed():      # отозвать XRay-доступ удалённого клиента
                xray_write_config(); xray_restart()
            send(chat, "✅ Клиент <b>%s</b> удалён." % e(c["name"] if c else pub))
            show(view_clients(chat))
        elif data == "add":
            pending[chat] = "add_name"
            show(("➕ <b>Новый клиент</b>\n\nОтправьте имя (например: <i>Мама iPhone</i>).\n/cancel — отмена", [BACK]))
        elif data == "adguard":
            show(view_adguard())
        elif data in ("agon", "agoff"):
            ag("POST", "/control/protection", {"enabled": data == "agon"})
            show(view_adguard())
        elif data == "ru":
            show(view_ru())
        elif data == "rusplit":
            payload, n = split_file()
            send_file(chat, "ip-list.json", payload,
                      "Список для AmneziaVPN: %d подсетей (российские + локальные сети)." % n, "application/json")
            send(chat, SPLIT_HOWTO)
            send(chat, "☝️ Перешлите файл и инструкцию пользователям.", [[btn("⬅️ Блокировка RU", "ru")], BACK])
        elif data == "ruupd":
            wait("Обновляю список российских сетей…")
            rc, out, err = run([RU_SCRIPT], timeout=240)
            res = (out.strip().splitlines() or [""])[-1] if rc == 0 else "ошибка: " + (err.strip() or out.strip())
            send(chat, ("✅ " if rc == 0 else "❌ ") + e(res))
            show(view_ru())
        elif data == "ruipoff":
            wait("Выключаю…")
            run(["systemctl", "disable", "--now", "block-ru.timer", "block-ru.service"])
            run([RU_SCRIPT, "stop"])
            set_kit_option("RU_BLOCK", 0)
            show(view_ru())
        elif data == "ruipon":
            wait("Включаю…")
            run(["systemctl", "enable", "block-ru.timer", "block-ru.service"])
            run(["systemctl", "start", "block-ru.timer"])
            run(["systemctl", "start", "block-ru.service"], timeout=240)
            set_kit_option("RU_BLOCK", 1)
            show(view_ru())
        elif data in ("rudnson", "rudnsoff"):
            set_ru_dns(data == "rudnson")
            set_kit_option("RU_DNS", 1 if data == "rudnson" else 0)
            show(view_ru())
        elif data == "service":
            show(view_service())
        elif data == "reptgl":
            order = ["daily", "weekly", "off"]
            cur = CFG.get("report", "daily")
            CFG["report"] = order[(order.index(cur) + 1) % 3]
            save_cfg()
            show(view_service())
        elif data == "srvname":
            pending[chat] = "srvname"
            show(("✏️ <b>Имя сервера</b>\n\nЭто название пользователи увидят в приложении AmneziaVPN "
                  "(в новых выданных конфигах). Сейчас: <b>%s</b>\n\nОтправьте новое имя. /cancel — отмена"
                  % e(srv_name()), [[btn("⬅️ Сервис", "service")]]))
        elif data == "backup":
            do_backup(chat)
            show(view_service())
        elif data == "bpass":
            show(view_bpass())
        elif data == "canary":
            show(view_canary())
        elif data == "obfs":
            show(view_obfs())
        elif data == "obfsrot":
            show(("🎲 Сменить маскировку (H1–H4)?\n\nVPN перезапустится, все текущие конфиги перестанут "
                  "подключаться — бот перевышлет новые клиентам с кабинетом, остальных раздадите вручную.\n"
                  "Перед сменой делается бэкап; если VPN не поднимется — автоматический откат.",
                  [[btn("✅ Да, сменить", "obfsok"), btn("❌ Отмена", "obfs")]]))
        elif data == "obfsok":
            do_rotate_obfs(chat)
        elif data == "obfsauto":
            CFG["auto_rotate"] = not CFG.get("auto_rotate")
            save_cfg()
            show(view_obfs())
        elif data == "xray":
            show(view_xray())
        elif data == "xrinstall":
            wait("Устанавливаю XRay (может занять минуту)…")
            try:
                ok, msg = install_xray()
            except Exception as ex:
                log("install_xray:", traceback.format_exc())
                ok, msg = False, str(ex)
            if ok:
                show(("✅ XRay установлен и запущен. Теперь выдавайте его клиентам в их карточке "
                      "(«🧅 Дать XRay»).", [[btn("⬅️ XRay", "xray")]]))
            else:
                show(("❌ Не удалось установить XRay: %s" % e(msg), [[btn("🔄 Ещё раз", "xrinstall")], [btn("⬅️ XRay", "xray")]]))
        elif data == "xrrestart":
            wait("Перезапускаю XRay…")
            xray_restart()
            show(view_xray())
        elif data == "xrsni":
            pending[chat] = "xrsni"
            show(("✏️ Отправьте домен для маскировки (SNI) — сайт с поддержкой TLS 1.3, "
                  "например <code>www.microsoft.com</code> или <code>dl.google.com</code>. Сейчас: <b>%s</b>\n"
                  "После смены выданные XRay-ссылки нужно перевыдать. /cancel — отмена" % e(xray_sni()),
                  [[btn("⬅️ XRay", "xray")]]))
        elif data == "xrremove":
            show(("🗑 Удалить XRay? Контейнер будет остановлен и удалён, XRay-доступ у клиентов перестанет "
                  "работать (AmneziaWG не затрагивается).",
                  [[btn("✅ Да, удалить", "xrremok"), btn("❌ Отмена", "xray")]]))
        elif data == "xrremok":
            wait("Удаляю XRay…")
            run(["docker", "rm", "-f", XRAY_CONTAINER], timeout=60)
            run(["ufw", "delete", "allow", "%d/tcp" % xray_cfg().get("port", 443)], timeout=30)
            for pub in list(CFG.get("clients", {})):
                if cdata(pub).get("xray_uuid"):
                    set_cdata(pub, xray_uuid=None)
            CFG.pop("xray", None)
            save_cfg()
            show(("✅ XRay удалён.", [[btn("⬅️ Сервис", "service")]]))
        elif data.startswith("cxray:"):
            pub = data[6:]
            give_xray(chat, pub)
            show(view_client(pub))
        elif data.startswith("cxroff:"):
            pub = data[7:]
            remove_xray(pub)
            send(chat, "🧅 XRay у клиента убран.")
            show(view_client(pub))
        elif data == "caninstall":
            wait("Готовлю команду установки…")
            try:
                cmd = canary_install_cmd(chat)
            except Exception as ex:
                show(("❌ Не удалось подготовить: %s" % e(str(ex)), [[btn("⬅️ Канарейка", "canary")]]))
            else:
                send(chat, "📋 Запустите это на Linux-хосте <b>в России</b> (от root):")
                send_file(chat, "install-canary.command.sh", cmd.encode(),
                          "Команда установки канарейки. Запуск: <code>bash install-canary.command.sh</code>")
                send(chat, "⚠️ Токен бота окажется на этом хосте. Хост должен быть в РФ (иначе проверка "
                           "бессмысленна). После установки канарейка сама пришлёт статус в этот чат.",
                     [[btn("⬅️ Канарейка", "canary")]])
        elif data == "canssh":
            pending[chat] = "canssh"
            show(("🔐 Отправьте данные SSH хоста канарейки одной строкой:\n"
                  "<code>root@IP пароль [метка]</code>\n"
                  "например: <code>root@203.0.113.9 S3cret МТС-Москва</code>\n\n"
                  "Пароль используется один раз и не сохраняется. После установки "
                  "удалите это сообщение с паролем. /cancel — отмена", [[btn("⬅️ Канарейка", "canary")]]))
        elif data == "bpgen":
            new = set_backup_pass("")
            send(chat, "✅ Новый случайный пароль бэкапа создан:\n<tg-spoiler><code>%s</code></tg-spoiler>\n\n"
                       "⚠️ Бэкапы, сделанные со старым паролем, теперь открываются только старым паролем." % e(new))
            show(view_bpass())
        elif data == "bpset":
            pending[chat] = "bpass"
            show(("✏️ Отправьте новый пароль бэкапа (минимум 6 символов). /cancel — отмена.\n\n"
                  "⚠️ Прежние бэкапы останутся на старом пароле.", [[btn("⬅️ Назад", "bpass")]]))
        elif data == "update":
            wait("Проверяю обновления…")
            nv = check_update()
            if not nv:
                show(("✅ Установлена последняя версия (%s)." % e(kit_option("KIT_VERSION", "?")),
                      [[btn("⬅️ Сервис", "service")], BACK]))
            else:
                show(("⬆️ Доступна версия <b>%s</b> (у вас %s).\n\nОбновление скачает установщик, проверит "
                      "контрольную сумму и перезапустит сервисы. Клиенты, настройки и параметры сохранятся."
                      % (e(str(nv)), e(kit_option("KIT_VERSION", "?"))),
                      [[btn("⬆️ Обновить сейчас", "doupd"), btn("❌ Отмена", "service")]]))
        elif data == "doupd":
            do_update(chat)
        elif data.startswith("ask:"):
            act = data[4:]
            back = "adguard" if act == "rag" else "service"
            show((CONFIRM.get(act, "Подтвердите действие"),
                  [[btn("✅ Да", "do:" + act), btn("❌ Отмена", back)]]))
        elif data == "do:rvpn":
            wait("Перезапускаю VPN…")
            rc, _, err = run(["docker", "restart", AWG_CONTAINER], timeout=120)
            container_pid_reset()
            time.sleep(3)
            run([VPN_NET_SCRIPT], timeout=60)
            send(chat, "✅ VPN перезапущен" if rc == 0 else "❌ Ошибка: " + e(err.strip()))
            show(view_status())
        elif data == "do:rag":
            wait("Перезапускаю AdGuard…")
            rc, _, err = run(["docker", "restart", ADGUARD_CONTAINER], timeout=120)
            time.sleep(5)
            run([VPN_NET_SCRIPT], timeout=60)
            send(chat, "✅ AdGuard перезапущен" if rc == 0 else "❌ Ошибка: " + e(err.strip()))
            show(view_adguard())
        elif data == "do:reboot":
            edit(chat, mid, "♻️ Перезагружаюсь… Напишу, когда сервер поднимется.")
            threading.Timer(2, lambda: run(["systemctl", "reboot"])).start()
    except Exception as ex:
        log("callback %s: %s" % (data, traceback.format_exc()))
        send(chat, "❌ Ошибка: %s" % e(str(ex)), [BACK])


def handle_precheckout(pcq):
    """Подтвердить предоплату в течение 10 сек, иначе Telegram отменит платёж."""
    ok = (pcq.get("invoice_payload", "").startswith("buy:")
          and tariff_by_id(pcq["invoice_payload"][4:]) is not None)
    params = {"pre_checkout_query_id": pcq["id"], "ok": ok}
    if not ok:
        params["error_message"] = "Тариф больше недоступен. Средства не списаны."
    tg("answerPreCheckoutQuery", params)


def handle_payment(uid, sp):
    """Начислить доступ после успешной оплаты (successful_payment)."""
    t = tariff_by_id((sp.get("invoice_payload") or "")[4:])
    charge = sp.get("telegram_payment_charge_id")
    stars = sp.get("total_amount")
    log("payment:", uid, sp.get("invoice_payload"), stars, charge)
    if not t:
        notify_admins("💳 Оплата %s⭐ от ID %s по неизвестному тарифу (%s). Разберитесь вручную; "
                      "charge_id: <code>%s</code>" % (stars, uid, e(sp.get("invoice_payload", "")), e(charge or "")))
        send(uid, "✅ Оплата получена. Администратор свяжется с вами по поводу доступа.")
        return
    try:
        apply_purchase(uid, t, charge_id=charge, stars=stars)
    except Exception:
        log("apply_purchase:", traceback.format_exc())
        notify_admins("⚠️ Оплата %s⭐ от ID %s прошла, но выдача доступа дала сбой. "
                      "charge_id: <code>%s</code>" % (stars, uid, e(charge or "")))
        send(uid, "✅ Оплата получена, но при выдаче доступа возникла ошибка. Администратор уже уведомлён.")


def handle_message(m):
    chat = m["chat"]["id"]
    uid = m.get("from", {}).get("id")
    if m.get("successful_payment"):
        handle_payment(uid, m["successful_payment"])
        return
    text = (m.get("text") or "").strip()
    if uid not in ADMINS:
        code = CFG.get("setup_code")
        parts = text.split()
        if not ADMINS and code and len(parts) == 2 and parts[0].startswith("/start") and parts[1] == code:
            ADMINS.add(uid)
            save_cfg()
            log("admin registered:", uid)
            send(chat, "✅ Вы зарегистрированы как администратор.")
            send(chat, *view_menu())
            return
        # обычный пользователь: личный кабинет / покупка / заявка на доступ
        send(chat, *view_cabinet(uid))
        return

    if pending.get(chat) == "add_name" and text and not text.startswith("/"):
        pending.pop(chat, None)
        do_add(chat, text)
        return

    pend = pending.get(chat, "")
    if pend.startswith(("exp:", "lim:")) and text and not text.startswith("/"):
        pending.pop(chat, None)
        do_set_limit(chat, pend[:3], pend[4:], text)
        return
    if pend == "srvname" and text and not text.startswith("/"):
        pending.pop(chat, None)
        CFG["server_name"] = re.sub(r"\s+", " ", text).strip()[:64]
        save_cfg()
        send(chat, "✅ Имя сервера: <b>%s</b>. Оно попадёт в новые выданные конфиги "
                   "(AmneziaVPN). Выданные ранее не меняются — при необходимости перевыдайте." % e(srv_name()))
        send(chat, *view_service())
        return
    if pend == "bpass" and text and not text.startswith("/"):
        if len(text.strip()) < 6:
            send(chat, "Пароль слишком короткий (нужно ≥ 6 символов). Попробуйте ещё раз или /cancel.")
            return
        pending.pop(chat, None)
        set_backup_pass(text)
        send(chat, "✅ Пароль бэкапа установлен. ⚠️ Прежние бэкапы открываются старым паролем.")
        send(chat, *view_service())
        return
    if pend.startswith("tset:") and text and not text.startswith("/"):
        pending.pop(chat, None)
        _, tid, field = pend.split(":")
        do_tariff_set(chat, tid, field, text)
        return
    if pend == "canssh" and text and not text.startswith("/"):
        pending.pop(chat, None)
        do_canary_ssh(chat, text)
        return
    if pend == "csearch" and text and not text.startswith("/"):
        pending.pop(chat, None)
        set_filter(chat, q=re.sub(r"\s+", " ", text).strip()[:40])
        send(chat, *view_clients(chat))
        return
    if pend == "xrsni" and text and not text.startswith("/"):
        sni = re.sub(r"[^A-Za-z0-9.-]", "", text.strip())[:80]
        if "." not in sni:
            send(chat, "Похоже, это не домен. Пример: www.microsoft.com. Повторите или /cancel.")
            return
        pending.pop(chat, None)
        xray_cfg()["sni"] = sni
        save_cfg()
        if xray_installed():
            xray_write_config()
            xray_restart()
        send(chat, "✅ Маскировка (SNI): <b>%s</b>. Перевыдайте XRay-ссылки клиентам (в карточке), "
                   "старые со старым SNI перестанут работать." % e(sni))
        send(chat, *view_xray())
        return

    cmd = text.split()[0].split("@")[0].lower() if text else ""
    arg = text.split(maxsplit=1)[1] if len(text.split(maxsplit=1)) > 1 else ""
    try:
        if cmd == "/status":
            send(chat, *view_status())
        elif cmd == "/clients":
            send(chat, *view_clients(chat))
        elif cmd == "/add":
            if arg:
                do_add(chat, arg)
            else:
                pending[chat] = "add_name"
                send(chat, "Отправьте имя нового клиента. /cancel — отмена")
        elif cmd == "/cancel":
            pending.pop(chat, None)
            send(chat, "Отменено.", MAIN_KB)
        elif cmd == "/addadmin" and arg.strip().lstrip("-").isdigit():
            ADMINS.add(int(arg.strip()))
            save_cfg()
            send(chat, "✅ Администратор %s добавлен." % e(arg.strip()))
        elif cmd == "/deladmin" and arg.strip().lstrip("-").isdigit():
            if int(arg.strip()) == uid:
                send(chat, "Нельзя удалить самого себя.")
            else:
                ADMINS.discard(int(arg.strip()))
                save_cfg()
                send(chat, "✅ Администратор %s удалён." % e(arg.strip()))
        elif cmd == "/admins":
            send(chat, "Администраторы: " + ", ".join("<code>%s</code>" % a for a in sorted(ADMINS)))
        else:
            send(chat, *view_menu())
    except Exception as ex:
        log("message %s: %s" % (cmd, traceback.format_exc()))
        send(chat, "❌ Ошибка: %s" % e(str(ex)), [BACK])


# ====================== мониторинг ======================
EGRESS_EVERY = 300        # как часто проверять выход сервера в интернет, сек
BLOCK_HS_RECENT = 300     # клиент «активен», если рукопожатие было за последние N сек
BLOCK_MIN_ACTIVE = 3      # минимум одновременно активных, чтобы массовый отвал был значимым
BLOCK_WINDOW = 900        # окно для пикового числа активных, сек
BLOCK_REALERT = 3600      # не чаще раза в час повторять тревогу о блокировке


def server_egress_ok():
    """Выходит ли сам сервер в интернет: TCP 443 к публичным IP (минуя DNS/AdGuard)."""
    for ip in ("1.1.1.1", "8.8.8.8"):
        rc, _, _ = dexec("nc", "-z", "-w", "4", ip, "443", timeout=12)
        if rc == 0:
            return True
    return False


def block_suspected(active_now, peak_active, egress_ok, secs_since_awg_change):
    """Похоже ли на блокировку: сервер исправен и в сети, но все недавно активные клиенты разом исчезли."""
    return bool(egress_ok) and active_now == 0 and peak_active >= BLOCK_MIN_ACTIVE and secs_since_awg_change > 180


def monitor():
    with open("/proc/uptime") as f:
        uptime = float(f.read().split()[0])
    if uptime < 600:
        time.sleep(20)
        notify_admins("🔌 Сервер загрузился (аптайм %s).\nVPN: %s · AdGuard: %s" % (
            dur(uptime), ok_icon(container_state(AWG_CONTAINER)[0]),
            ok_icon(container_state(ADGUARD_CONTAINER)[0])))
    cont = {}
    flags = {"disk": False, "mem": False, "reboot": False}
    seen = None   # pub -> был ли когда-либо handshake
    last_report = today_str()   # при старте не слать отчёт за «сегодня»
    active_hist = collections.deque()     # (ts, число активных клиентов)
    last_egress = 0.0; egress_ok = True; egress_alerted = False
    block_alerted = 0.0; awg_changed_at = time.time(); last_auto_rotate = 0.0
    titles = {AWG_CONTAINER: "VPN (AmneziaWG)", ADGUARD_CONTAINER: "AdGuard Home"}
    while True:
        alerts = []
        try:
            for name, title in titles.items():
                st = container_state(name)
                prev = cont.get(name)
                if prev is not None:
                    if prev[0] and not st[0]:
                        alerts.append("🔴 %s: контейнер остановлен!" % title)
                    elif not prev[0] and st[0]:
                        alerts.append("🟢 %s: снова работает" % title)
                    elif st[0] and prev[1] != st[1]:
                        alerts.append("🔄 %s: контейнер перезапустился" % title)
                    if name == AWG_CONTAINER and st != prev:
                        awg_changed_at = time.time()   # после перезапуска VPN рукопожатия сбрасываются
                cont[name] = st

            d = shutil.disk_usage("/")
            pct = 100.0 * d.used / d.total
            if pct > 90 and not flags["disk"]:
                alerts.append("💿 Диск заполнен на %.0f%%!" % pct)
                flags["disk"] = True
            elif pct < 85:
                flags["disk"] = False

            total, avail = meminfo()
            if avail < total * 0.08 and not flags["mem"]:
                alerts.append("💾 Мало свободной памяти: %s" % hb(avail))
                flags["mem"] = True
            elif avail > total * 0.15:
                flags["mem"] = False

            rr = os.path.exists("/var/run/reboot-required")
            if rr and not flags["reboot"]:
                alerts.append("⚠️ Установлены обновления, требующие перезагрузки. "
                              "Сервер перезагрузится автоматически в 04:00.")
            flags["reboot"] = rr

            if container_state(AWG_CONTAINER)[0]:
                write_blocked_file()
                enforce_blocked()
                check_access(account_traffic())   # сроки и лимиты
                cl = get_clients()
                if seen is not None:
                    for c in cl:
                        if c["hs"] and not seen.get(c["pub"]):
                            alerts.append("🆕 Клиент <b>%s</b> подключился впервые" % e(c["name"]))
                seen = {c["pub"]: bool(c["hs"]) or (seen or {}).get(c["pub"], False) for c in cl}

                # автопроверка доступности: выход сервера в интернет + массовый отвал клиентов
                now_ts = time.time()
                active = sum(1 for c in cl if c["hs"] and now_ts - c["hs"] < BLOCK_HS_RECENT)
                active_hist.append((now_ts, active))
                while active_hist and now_ts - active_hist[0][0] > BLOCK_WINDOW:
                    active_hist.popleft()
                peak = max((a for _, a in active_hist), default=0)
                if now_ts - last_egress >= EGRESS_EVERY:
                    last_egress = now_ts
                    egress_ok = server_egress_ok()
                    if not egress_ok and not egress_alerted:
                        alerts.append("🔴 Сервер не выходит в интернет — у клиентов VPN не работает. "
                                      "Проверьте сеть сервера/хостера.")
                        egress_alerted = True
                    elif egress_ok and egress_alerted:
                        alerts.append("🟢 Выход сервера в интернет восстановлен.")
                        egress_alerted = False
                if (block_suspected(active, peak, egress_ok, now_ts - awg_changed_at)
                        and now_ts - block_alerted > BLOCK_REALERT):
                    block_alerted = now_ts
                    alerts.append("⚠️ Возможно, VPN заблокирован провайдером: сервер исправен и выходит "
                                  "в интернет, но все недавно активные клиенты (до %d) разом отключились. "
                                  "Проверьте доступность у пользователей — возможно, режут IP или порт." % peak)
                    # опциональная авто-смена маскировки (по умолчанию выключена), не чаще раза в 6 ч
                    if CFG.get("auto_rotate") and now_ts - last_auto_rotate > 21600:
                        last_auto_rotate = now_ts
                        try:
                            nv = gen_headers()
                            ok, msg = set_obfs_headers(nv)
                            if ok:
                                r, _, _ = reissue_after_rotation(nv)
                                awg_changed_at = time.time()
                                notify_admins("🔄 Авто-смена маскировки из-за подозрения на блок. "
                                              "Новые конфиги отправлены клиентам с кабинетом: %d. "
                                              "Проверьте доступность (и канарейку, если есть)." % len(r))
                            else:
                                notify_admins("⚠️ Авто-смена маскировки не удалась: %s" % e(msg))
                        except Exception:
                            log("auto_rotate:", traceback.format_exc())

            # раз в день в REPORT_HOUR: отчёт (если включён) и проверка обновлений
            now = time.localtime()
            if now.tm_hour >= REPORT_HOUR and today_str() != last_report:
                last_report = today_str()
                mode = CFG.get("report", "daily")
                if mode != "off" and (mode == "daily" or now.tm_wday == 0):
                    try:
                        notify_admins(build_report())
                    except Exception:
                        log("report:", traceback.format_exc())
                prev_nv = CFG.get("update_available")
                nv = check_update()
                if nv and nv != prev_nv:
                    notify_admins("⬆️ Доступна новая версия набора: <b>%s</b> (у вас %s). "
                                  "Обновить: ⚙️ Сервис → «Обновить набор»." % (
                                      e(str(nv)), e(kit_option("KIT_VERSION", "?"))))
        except Exception:
            log("monitor:", traceback.format_exc())
        if alerts:
            notify_admins("\n".join(alerts))
        time.sleep(60)


# ====================== один конфиг на нескольких устройствах ======================
def alert_shared(pub, eps, nchg, nhs):
    c = find_client(pub)
    name = c["name"] if c else pub[:8]
    ips = sorted({x.rsplit(":", 1)[0] for x in eps})
    where = ", ".join("<code>%s</code>" % e(i) for i in ips) or "—"
    if len(ips) == 1 and len(eps) > 1:
        where += " (один IP, разные порты — устройства, вероятно, в одной сети)"
    text = ("⚠️ Похоже, конфиг <b>%s</b> используется на нескольких устройствах одновременно.\n\n"
            "За последние 5 минут: смен адреса — %d, переподключений — %d "
            "(у одного устройства обычно 0–3).\nАдреса: %s\n\n"
            "🔑 <b>Новый ключ</b> — все копии конфига перестанут работать, бот пришлёт новый для владельца.\n"
            "⛔ <b>Отключить</b> — доступ закрыт, пока вы не включите его обратно.") % (e(name), nchg, nhs, where)
    kb = [[btn("🔑 Новый ключ", "crk:" + pub), btn("⛔ Отключить", "cblk:" + pub)],
          [btn("🔕 Игнорировать сутки", "shign:" + pub)]]
    log("shared config suspected:", name, nchg, nhs, ips)
    for a in ADMINS:
        send(a, text, kb)


def share_suspected(n_endpoints, n_changes, n_handshakes):
    """Похоже ли, что один ключ одновременно используют несколько устройств (за окно SHARE_WINDOW)."""
    return n_endpoints >= 2 and (
        (n_changes >= SHARE_MIN_EP_CHANGES and n_handshakes >= SHARE_MIN_HANDSHAKES)
        or n_changes >= SHARE_EP_ALONE)


def share_watch():
    """Один ключ на двух устройствах: сервер «перескакивает» между их адресами и часто
    повторяет рукопожатие. Считаем смены адреса и рукопожатия в скользящем окне."""
    hist, alerted = {}, {}
    while True:
        try:
            try:
                peers = uapi_peers()
            except Exception:
                peers = {p: {"endpoint": "" if d["endpoint"] == "(none)" else d["endpoint"], "hs": d["hs"]}
                         for p, d in awg_dump().items()}
            now = time.time()
            for pub, p in peers.items():
                h = hist.get(pub)
                if h is None:
                    hist[pub] = {"ep": p["endpoint"], "hs": p["hs"],
                                 "chg": collections.deque(), "hss": collections.deque()}
                    continue
                if p["endpoint"] and p["endpoint"] != h["ep"]:
                    h["chg"].append((now, h["ep"], p["endpoint"]))
                    h["ep"] = p["endpoint"]
                if p["hs"] and p["hs"] != h["hs"]:
                    h["hss"].append(now)
                    h["hs"] = p["hs"]
                while h["chg"] and now - h["chg"][0][0] > SHARE_WINDOW:
                    h["chg"].popleft()
                while h["hss"] and now - h["hss"][0] > SHARE_WINDOW:
                    h["hss"].popleft()
                eps = {x for _, a, b in h["chg"] for x in (a, b) if x}
                nchg, nhs = len(h["chg"]), len(h["hss"])
                if (share_suspected(len(eps), nchg, nhs)
                        and now - alerted.get(pub, 0) > SHARE_REALERT
                        and now > CFG.get("share_mute", {}).get(pub, 0)
                        and not is_blocked(pub)):
                    alerted[pub] = now
                    alert_shared(pub, eps, len(h["chg"]), len(h["hss"]))
            for pub in list(hist):
                if pub not in peers:
                    del hist[pub]
        except Exception:
            log("share_watch:", traceback.format_exc())
        time.sleep(SHARE_POLL)


# ====================== main ======================
def dispatch_update(u):
    try:
        if "callback_query" in u:
            handle_callback(u["callback_query"])
        elif "pre_checkout_query" in u:
            handle_precheckout(u["pre_checkout_query"])
        elif "message" in u:
            handle_message(u["message"])
    except Exception:
        log("update:", traceback.format_exc())


def main():
    if not CFG.get("token"):
        log("Токен не задан в", CONFIG_PATH)
        raise SystemExit(1)
    me = tg("getMe")
    if not me.get("ok"):
        log("getMe failed:", me)
        time.sleep(60)
        raise SystemExit(1)
    log("started as @%s, admins: %s" % (me["result"]["username"], sorted(ADMINS) or "нет (ожидается /start <код>)"))
    # сообщить об успешном обновлении (установщик перезапустил бота)
    if os.path.exists(UPDATE_SENTINEL):
        try:
            with open(UPDATE_SENTINEL, encoding="utf-8") as f:
                ver = f.read().strip()
            os.remove(UPDATE_SENTINEL)
            CFG["update_available"] = None
            save_cfg()
            notify_admins("✅ Набор обновлён. Текущая версия: <b>%s</b>." % e(kit_option("KIT_VERSION", ver)))
        except Exception:
            log("update sentinel:", traceback.format_exc())
    tg("setMyCommands", {"commands": [
        {"command": "menu", "description": "Главное меню"},
        {"command": "status", "description": "Состояние сервера"},
        {"command": "clients", "description": "Клиенты VPN"},
        {"command": "add", "description": "Создать клиента: /add Имя"},
    ]})
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=share_watch, daemon=True).start()
    offset = None
    while True:
        try:
            r = tg("getUpdates", {"timeout": 50, "offset": offset,
                                  "allowed_updates": ["message", "callback_query", "pre_checkout_query"]}, timeout=70)
            if not r.get("ok"):
                log("getUpdates:", r.get("description"))
                time.sleep(10)
                continue
            for u in r["result"]:
                offset = u["update_id"] + 1
                # каждое обновление — в своём потоке, чтобы долгая операция
                # (проверка сети, анализ трафика, смена маскировки, установка по SSH)
                # не блокировала ответы на остальные нажатия
                threading.Thread(target=dispatch_update, args=(u,), daemon=True).start()
        except Exception as ex:
            log("poll error:", ex)
            time.sleep(5)


if __name__ == "__main__":
    main()
VPNKIT_EOF_FILE_BOT_PY
}

file_vpn_bot_service() {
put /etc/systemd/system/vpn-bot.service 644 <<'VPNKIT_EOF_FILE_VPN_BOT_SERVICE'
[Unit]
Description=Telegram panel for VPN server
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 -u /opt/vpn-bot/bot.py
Restart=always
RestartSec=10
Environment=LC_ALL=C.UTF-8

[Install]
WantedBy=multi-user.target
VPNKIT_EOF_FILE_VPN_BOT_SERVICE
}

file_vpn_bot_token() {
put /usr/local/sbin/vpn-bot-token 755 <<'VPNKIT_EOF_FILE_VPN_BOT_TOKEN'
#!/bin/bash
# Задать токен Telegram-бота и запустить его:  vpn-bot-token 123456:ABC-DEF...
set -euo pipefail
T="${1:-}"
[ -n "$T" ] || { echo "Использование: vpn-bot-token <токен от @BotFather>"; exit 1; }
ME=$(curl -fsS --max-time 15 "https://api.telegram.org/bot$T/getMe") || { echo "Telegram не принял токен"; exit 1; }
python3 - "$T" <<'PY'
import json, sys, secrets, os
p = "/etc/vpn-bot/config.json"
c = json.load(open(p)) if os.path.exists(p) else {}
c["token"] = sys.argv[1]
c.setdefault("admins", [])
c.setdefault("setup_code", secrets.token_hex(4))
json.dump(c, open(p, "w"), indent=2)
PY
chmod 600 /etc/vpn-bot/config.json
systemctl enable vpn-bot.service >/dev/null 2>&1
systemctl restart vpn-bot.service
U=$(echo "$ME" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["username"])')
CODE=$(python3 -c 'import json; print(json.load(open("/etc/vpn-bot/config.json"))["setup_code"])')
ADM=$(python3 -c 'import json; print(len(json.load(open("/etc/vpn-bot/config.json"))["admins"]))')
echo "Бот @$U запущен."
[ "$ADM" = 0 ] && echo "Откройте его в Telegram и отправьте:  /start $CODE" || true
VPNKIT_EOF_FILE_VPN_BOT_TOKEN
}


# ---------------------------------------------------------------------
detect() {
  say "Проверка сервера"
  [ "$(id -u)" = 0 ] || die "Запустите от root (sudo -i)"
  command -v apt-get >/dev/null || die "Поддерживаются только Ubuntu/Debian"
  command -v docker >/dev/null || die "Docker не найден. Сначала установите AmneziaWG на этот сервер через приложение Amnezia."
  AWG_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E '^amnezia-awg' | head -n1 || true)
  [ -n "$AWG_CONTAINER" ] || die "Не найден работающий контейнер AmneziaWG. Установите протокол AmneziaWG через приложение Amnezia и запустите скрипт снова."
  AWG_CONF=$(docker exec "$AWG_CONTAINER" sh -c 'ls /opt/amnezia/awg/*.conf 2>/dev/null' | head -n1 || true)
  [ -n "$AWG_CONF" ] || die "В контейнере $AWG_CONTAINER нет конфига /opt/amnezia/awg/*.conf"
  AWG_DIR=$(dirname "$AWG_CONF")
  AWG_IF=$(basename "$AWG_CONF" .conf)
  AWG_PORT=$(docker exec "$AWG_CONTAINER" cat "$AWG_CONF" | awk -F'=' '/^[[:space:]]*ListenPort/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' || true)
  local subnet
  subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' amnezia-dns-net 2>/dev/null || true)
  [ "$subnet" = "172.29.172.0/24" ] || die "Сеть Docker amnezia-dns-net не найдена или нестандартная (${subnet:-нет}). Её создаёт приложение Amnezia."
  WAN=$(ip -4 route show default | awk '{print $5; exit}')
  [ -n "$WAN" ] || die "Не найден внешний сетевой интерфейс"
  ok "AmneziaWG: контейнер $AWG_CONTAINER, интерфейс $AWG_IF, порт ${AWG_PORT:-?}/udp"
  ok "Внешний интерфейс: $WAN"
}

save_options() {
  put "$OPTIONS_FILE" 644 <<EOF
# Amnezia Server Kit: параметры установки. Повторный запуск установщика их учитывает,
# бот меняет RU_BLOCK и RU_DNS, когда вы переключаете блокировку в его меню.
KIT_VERSION=$KIT_VERSION
RU_BLOCK=$RU_BLOCK
RU_DNS=$RU_DNS
ADGUARD=$ADGUARD
AUTO_REBOOT=$AUTO_REBOOT
BOT=$BOT
EOF
}

install_packages() {
  say "Установка пакетов (может занять несколько минут)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=1800 update -q >/dev/null
  apt-get -o DPkg::Lock::Timeout=1800 install -y -q ipset curl ufw fail2ban unattended-upgrades \
    qrencode python3 iproute2 util-linux openssh-client sshpass >/tmp/vpnkit-apt.log 2>&1 \
    || { tail -15 /tmp/vpnkit-apt.log; die "Не удалось установить пакеты"; }
  ok "ipset, ufw, fail2ban, unattended-upgrades, qrencode, ssh/sshpass"
}

setup_bbr() {
  say "BBR (ускорение TCP)"
  echo tcp_bbr > /etc/modules-load.d/bbr.conf
  modprobe tcp_bbr 2>/dev/null || true
  put /etc/sysctl.d/99-bbr.conf 644 <<'EOF'
# BBR congestion control (fq qdisc)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl -q -p /etc/sysctl.d/99-bbr.conf || warn "не удалось применить BBR сейчас — применится после перезагрузки"
  tc qdisc replace dev "$WAN" root fq 2>/dev/null || true
  ok "TCP: $(sysctl -n net.ipv4.tcp_congestion_control)"
}

setup_updates() {
  say "Автоматические обновления безопасности"
  put /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  local reboot=false; [ "$AUTO_REBOOT" = 1 ] && reboot=true
  put /etc/apt/apt.conf.d/52unattended-upgrades-local 644 <<EOF
// Amnezia Server Kit: перезагрузка, если обновление ядра/библиотек её требует — ночью
Unattended-Upgrade::Automatic-Reboot "$reboot";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
  systemctl enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  if [ "$AUTO_REBOOT" = 1 ]; then ok "включены, перезагрузка при необходимости — в 04:00"; else ok "включены, без автоперезагрузки"; fi
}

setup_ru_block() {
  say "Блокировка российских IP-адресов для клиентов VPN"
  file_block_ru_sh; file_block_ru_service; file_block_ru_timer
  systemctl daemon-reload
  if [ "$RU_BLOCK" = 1 ]; then
    systemctl enable block-ru.service block-ru.timer >/dev/null 2>&1
    systemctl start block-ru.timer
    systemctl restart block-ru.service || warn "не удалось скачать список — повторю при следующем запуске таймера"
    ok "$(ipset list ru_v4 -t 2>/dev/null | awk '/entries/ {print $4}' || true) сетей, обновление — еженедельно"
  else
    systemctl disable --now block-ru.timer block-ru.service >/dev/null 2>&1 || true
    /usr/local/sbin/block-ru.sh stop >/dev/null 2>&1 || true
    ok "пропущено (--no-ru-block)"
  fi
}

ag_api() {   # ag_api <метод> <путь> [json]
  local pass
  pass=$(sed -n 's/^Password: //p' /root/adguard-admin.txt)
  curl -fsS -o /dev/null -u "admin:$pass" -X "$1" "http://$AG_IP$2" -H 'Content-Type: application/json' ${3:+-d "$3"}
}

setup_adguard() {
  say "AdGuard Home (свой DNS для клиентов VPN)"
  if [ "$ADGUARD" != 1 ]; then ok "пропущено (--no-adguard)"; return 0; fi
  if docker inspect adguardhome >/dev/null 2>&1; then
    docker start adguardhome >/dev/null 2>&1 || true
    ok "уже установлен — настройки не трогаю"
    return 0
  fi
  docker pull -q adguard/adguardhome:latest >/dev/null
  mkdir -p /opt/adguardhome/work /opt/adguardhome/conf
  docker run -d --name adguardhome --restart unless-stopped \
    --network amnezia-dns-net --ip "$AG_IP" --memory 300m \
    -v /opt/adguardhome/work:/opt/adguardhome/work \
    -v /opt/adguardhome/conf:/opt/adguardhome/conf \
    adguard/adguardhome:latest >/dev/null
  # восстановленный из бэкапа AdGuard уже настроен — не трогаем конфигурацию
  if [ -f /opt/adguardhome/conf/AdGuardHome.yaml ] && [ -f /root/adguard-admin.txt ]; then
    for _ in $(seq 1 60); do curl -fs -o /dev/null -u "admin:$(sed -n 's/^Password: //p' /root/adguard-admin.txt)" "http://$AG_IP/control/status" && break; sleep 1; done
    ok "восстановлен из бэкапа — настройки и пароль сохранены"
    return 0
  fi
  local pass
  for _ in $(seq 1 60); do curl -fs -o /dev/null "http://$AG_IP:3000/control/install/get_addresses" && break; sleep 1; done
  pass=$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))')
  (umask 077; printf 'AdGuard Home\nURL (только через VPN): http://%s\nLogin: admin\nPassword: %s\n' "$AG_IP" "$pass" > /root/adguard-admin.txt)
  curl -fsS -o /dev/null -X POST "http://$AG_IP:3000/control/install/configure" -H 'Content-Type: application/json' \
    -d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":80},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"admin\",\"password\":\"$pass\"}"
  for _ in $(seq 1 60); do curl -fs -o /dev/null -u "admin:$pass" "http://$AG_IP/control/status" && break; sleep 1; done
  # DNS-over-HTTPS наружу; без лимита запросов (все клиенты VPN могут прийти с одного адреса)
  ag_api POST /control/dns_config '{"upstream_dns":["https://dns.cloudflare.com/dns-query","https://dns.quad9.net/dns-query"],"bootstrap_dns":["1.1.1.1","9.9.9.9"],"fallback_dns":["1.1.1.1","9.9.9.9"],"upstream_mode":"parallel","ratelimit":0,"cache_size":8388608,"cache_optimistic":true,"dnssec_enabled":true}'
  ag_api PUT /control/querylog/config/update '{"enabled":true,"interval":86400000,"anonymize_client_ip":false,"ignored":[]}'
  ag_api PUT /control/stats/config/update '{"enabled":true,"interval":604800000,"ignored":[]}'
  if [ "$RU_DNS" = 1 ]; then
    ag_api POST /control/filtering/set_rules '{"rules":["! Российские доменные зоны (дополнение к блокировке по IP)","||ru^","||xn--p1ai^","||su^"]}'
  fi
  ok "установлен: http://$AG_IP (открывается только через VPN), логин и пароль — в /root/adguard-admin.txt"
}

setup_vpn_net() {
  say "Правила для клиентов VPN (SMTP, DNS → AdGuard, статистика по клиентам)"
  mkdir -p /var/lib/vpn-bot && chmod 700 /var/lib/vpn-bot
  file_adguard_sync_clients; file_vpn_net_sh; file_vpn_net_service; file_vpn_net_timer
  systemctl daemon-reload
  systemctl enable vpn-net.service vpn-net.timer >/dev/null 2>&1
  systemctl start vpn-net.timer
  /usr/local/sbin/vpn-net.sh >/dev/null || true
  ok "исходящий порт 25 закрыт, DNS клиентов идёт в AdGuard, правила проверяются каждую минуту"
}

setup_ufw() {
  say "Межсетевой экран (входящие)"
  local ports p
  ports=$( { echo "${SSH_CONNECTION:-}" | awk '{print $4}'
             sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
             ss -tlnpH 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print a[n]}'
           } | grep -E '^[0-9]+$' | sort -un || true)
  [ -n "$ports" ] || ports=22
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for p in $ports; do ufw allow "$p/tcp" comment 'SSH' >/dev/null; done
  if [ -n "${AWG_PORT:-}" ]; then ufw allow "$AWG_PORT/udp" comment 'AmneziaWG' >/dev/null; fi
  ufw deny out 25/tcp comment 'no SMTP' >/dev/null
  sed -i 's/^\(-A ufw-before-input -p icmp --icmp-type echo-request -j\) ACCEPT/\1 DROP/' /etc/ufw/before.rules
  ufw --force enable >/dev/null
  iptables -D INPUT -p icmp -m icmp --icmp-type 8 -j DROP 2>/dev/null || true
  ok "открыты: SSH ($(printf '%s\n' "$ports" | paste -sd, -)/tcp), AmneziaWG (${AWG_PORT:-?}/udp); ping скрыт"
  ok "новые протоколы, добавленные через приложение Amnezia, будут работать без настройки (Docker)"
}

setup_fail2ban() {
  say "fail2ban (защита SSH от перебора пароля)"
  put /etc/fail2ban/jail.d/sshd-local.conf 644 <<'EOF'
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  ok "5 неудачных попыток входа → блокировка IP на 1 час"
}

setup_bot() {
  say "Telegram-бот для управления сервером"
  if [ "$BOT" != 1 ]; then ok "пропущено (--no-bot)"; return 0; fi
  mkdir -p /opt/vpn-bot /etc/vpn-bot /var/lib/vpn-bot/clients
  chmod 700 /etc/vpn-bot /var/lib/vpn-bot /var/lib/vpn-bot/clients
  file_bot_py; file_vpn_bot_service; file_vpn_bot_token
  python3 -m py_compile /opt/vpn-bot/bot.py
  AWG_CONTAINER="$AWG_CONTAINER" AWG_DIR="$AWG_DIR" AWG_IF="$AWG_IF" python3 - <<'PY'
import json, os, secrets
p = "/etc/vpn-bot/config.json"
c = json.load(open(p)) if os.path.exists(p) else {}
c.setdefault("token", "")
c.setdefault("admins", [])
c.setdefault("setup_code", secrets.token_hex(4))
c.update(awg_container=os.environ["AWG_CONTAINER"], awg_dir=os.environ["AWG_DIR"], awg_if=os.environ["AWG_IF"])
tmp = p + ".tmp"
json.dump(c, open(tmp, "w"), indent=2, ensure_ascii=False)
os.chmod(tmp, 0o600)
os.replace(tmp, p)
PY
  systemctl daemon-reload
  if [ -n "$TOKEN" ]; then
    /usr/local/sbin/vpn-bot-token "$TOKEN" >/dev/null || die "Telegram не принял токен бота"
  elif python3 -c 'import json, sys; sys.exit(0 if json.load(open("/etc/vpn-bot/config.json"))["token"] else 1)'; then
    systemctl enable vpn-bot.service >/dev/null 2>&1
    systemctl restart vpn-bot.service
  fi
  if systemctl is-active -q vpn-bot.service; then ok "бот запущен"; else warn "бот установлен, но не запущен — нужен токен (см. ниже)"; fi
}

selftest() {
  say "Проверка"
  sleep 3
  if docker exec "$AWG_CONTAINER" nc -z -w 5 google.com 443 2>/dev/null; then ok "google.com открывается из VPN"
  else warn "google.com не открывается из VPN — проверьте сеть сервера"; fi
  if [ "$RU_BLOCK" = 1 ]; then
    if docker exec "$AWG_CONTAINER" nc -z -w 5 ya.ru 443 2>/dev/null; then warn "ya.ru открывается из VPN — блокировка RU не сработала"
    else ok "ya.ru заблокирован для клиентов VPN"; fi
  fi
  if [ "$ADGUARD" = 1 ]; then
    if docker exec "$AWG_CONTAINER" iptables -t nat -S PREROUTING 2>/dev/null | grep -q "$AG_IP"; then ok "DNS клиентов перенаправлен в AdGuard"
    else warn "DNS-перенаправление ещё не включено (проверьте через минуту: vpn-net.sh)"; fi
  fi
  for u in ufw fail2ban unattended-upgrades vpn-net.timer; do
    if systemctl is-active -q "$u"; then ok "$u работает"; else warn "$u не работает"; fi
  done
}

summary() {
  say "Готово (Amnezia Server Kit $KIT_VERSION)"
  if [ "$BOT" = 1 ]; then
    local tok adm code
    tok=$(python3 -c 'import json; print("1" if json.load(open("/etc/vpn-bot/config.json"))["token"] else "")')
    adm=$(python3 -c 'import json; print(len(json.load(open("/etc/vpn-bot/config.json"))["admins"]))')
    code=$(python3 -c 'import json; print(json.load(open("/etc/vpn-bot/config.json"))["setup_code"])')
    if [ -z "$tok" ]; then
      echo
      echo "  Бот ждёт токен. В Telegram: @BotFather → /newbot → скопируйте токен и выполните:"
      echo "      vpn-bot-token <токен>"
      echo "  Для каждого сервера нужен свой бот (один токен нельзя запустить на двух серверах)."
    fi
    if [ "$adm" = 0 ]; then
      echo
      echo "  Чтобы стать администратором бота, отправьте ему:   /start $code"
    fi
  fi
  if [ "$ADGUARD" = 1 ] && [ -f /root/adguard-admin.txt ]; then
    echo
    echo "  Веб-панель AdGuard (только при включённом VPN): http://$AG_IP"
    echo "  Логин и пароль: cat /root/adguard-admin.txt   (также показываются в боте)"
  fi
  echo
}

uninstall() {
  [ "$(id -u)" = 0 ] || die "Запустите от root (sudo -i)"
  say "Удаление Amnezia Server Kit"
  cat <<'EOF'
   Будут удалены: Telegram-бот, AdGuard Home (с настройками и статистикой), блокировка RU,
   правила для клиентов VPN (SMTP, DNS → AdGuard, детский режим, отключённые клиенты).
   Останутся: AmneziaWG и все клиенты (в том числе созданные ботом), ufw, fail2ban,
   автообновления и BBR. Контейнер VPN перезапустится, клиенты переподключатся за ~10 секунд.
EOF
  local nblocked
  nblocked=$(python3 -c 'import json; print(len(json.load(open("/etc/vpn-bot/config.json")).get("blocked", [])))' 2>/dev/null || echo 0)
  if [ "${nblocked:-0}" -gt 0 ]; then
    warn "клиентов, отключённых в боте: $nblocked — после удаления они снова получат доступ."
    warn "Если это не нужно, сначала удалите их в боте или в приложении Amnezia."
  fi
  if [ "$YES" != 1 ]; then
    local ans=""
    { read -r -p "   Удалить? [y/N] " ans </dev/tty; } 2>/dev/null || true
    case "$ans" in
      y|Y|yes|д|Д|да|Да) ;;
      *) echo "   Отменено. Без вопросов: bash install-vpn-kit.sh --uninstall --yes"; exit 0 ;;
    esac
  fi

  systemctl disable --now vpn-bot.service vpn-net.timer vpn-net.service block-ru.timer block-ru.service >/dev/null 2>&1 || true
  if [ -x /usr/local/sbin/block-ru.sh ]; then /usr/local/sbin/block-ru.sh stop >/dev/null 2>&1 || true; fi
  ok "сервисы остановлены, блокировка RU снята"

  local wan chain bridge net c
  wan=$(ip -4 route show default | awk '{print $5; exit}')
  if iptables -n -L DOCKER-USER >/dev/null 2>&1; then chain=DOCKER-USER; else chain=FORWARD; fi
  if [ -n "$wan" ]; then
    while iptables -D "$chain" -o "$wan" -p tcp --dport 25 -j REJECT --reject-with tcp-reset 2>/dev/null; do :; done
  fi
  bridge=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' amnezia-dns-net 2>/dev/null || true)
  [ -n "$bridge" ] || bridge=amn0
  for net in $(ip -4 route show dev "$bridge" 2>/dev/null | awk '/ via / {print $1}'); do
    ip route del "$net" dev "$bridge" 2>/dev/null || true
  done
  docker rm -f adguardhome >/dev/null 2>&1 || true
  ok "AdGuard Home удалён, правила SMTP и маршруты сняты"

  rm -rf /opt/vpn-bot /etc/vpn-bot /var/lib/vpn-bot /var/lib/block-ru /opt/adguardhome /etc/vpn-kit \
         /root/adguard-admin.txt /run/adguard-sync.lock \
         /usr/local/sbin/{block-ru.sh,vpn-net.sh,adguard-sync-clients,vpn-bot-token} \
         /etc/systemd/system/{vpn-bot.service,vpn-net.service,vpn-net.timer,block-ru.service,block-ru.timer}
  systemctl daemon-reload
  ok "файлы удалены"

  # Правила внутри контейнеров VPN (DNS → AdGuard, детский режим, отключённые) сбрасываются перезапуском.
  # Без этого DNS клиентов уходил бы на удалённый AdGuard.
  for c in $(docker ps --format '{{.Names}}' | grep '^amnezia-' | grep -v '^amnezia-dns' || true); do
    docker restart "$c" >/dev/null && ok "перезапущен $c"
  done
  say "Amnezia Server Kit удалён"
  echo "   ufw, fail2ban, автообновления и BBR остались. Отключить межсетевой экран: ufw disable"
  echo
}

restore() {
  say "Восстановление из бэкапа"
  [ "$(id -u)" = 0 ] || die "Запустите от root (sudo -i)"
  [ -f "$RESTORE" ] || die "Файл бэкапа не найден: $RESTORE"
  command -v openssl >/dev/null || { apt-get update -q >/dev/null 2>&1; apt-get install -y -q openssl >/dev/null 2>&1; }
  command -v openssl >/dev/null || die "Не найден openssl для расшифровки"
  local pass="$RESTORE_PASS"
  if [ -z "$pass" ]; then
    printf '   Пароль бэкапа (его показал бот при первом бэкапе): '
    read -rs pass </dev/tty 2>/dev/null || die "Пароль не задан. Повторите с --pass <пароль>"
    echo
  fi
  [ -n "$pass" ] || die "Пустой пароль"
  # проверяем пароль и распаковываем во временную папку, затем переносим в /
  local tmp; tmp=$(mktemp -d)
  if ! VPNKIT_P="$pass" openssl enc -d -aes-256-cbc -pbkdf2 -pass env:VPNKIT_P -in "$RESTORE" 2>/dev/null \
       | tar xzf - -C "$tmp" 2>/dev/null; then
    rm -rf "$tmp"; die "Не удалось расшифровать — неверный пароль или повреждённый файл"
  fi
  [ -d "$tmp/etc/vpn-bot" ] || { rm -rf "$tmp"; die "В архиве нет данных бота — это не бэкап Amnezia Server Kit"; }
  cp -a "$tmp/." / 2>/dev/null || true
  rm -rf "$tmp"
  ok "файлы бэкапа восстановлены (клиенты, ключи, настройки AdGuard и бота)"
  # восстановленные параметры установки учитываем дальше
  if [ -r "$OPTIONS_FILE" ]; then
    local k v
    while IFS='=' read -r k v; do
      case "$k" in RU_BLOCK|RU_DNS|ADGUARD|AUTO_REBOOT|BOT) [[ "$v" =~ ^[01]$ ]] && printf -v "$k" '%s' "$v" ;; esac
    done < "$OPTIONS_FILE"
  fi
}

if [ "$UNINSTALL" = 1 ]; then
  uninstall
  exit 0
fi

if [ -n "$RESTORE" ]; then
  restore
fi

detect
install_packages
setup_bbr
setup_updates
setup_ru_block
setup_adguard
setup_vpn_net
setup_ufw
setup_fail2ban
setup_bot
selftest
save_options
summary
