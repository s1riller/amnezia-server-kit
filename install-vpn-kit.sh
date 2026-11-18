#!/bin/bash
# =====================================================================
#  VPN Server Kit — надстройки для сервера Amnezia (AmneziaWG)
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
KIT_VERSION="1.1"
AG_IP=172.29.172.253
OPTIONS_FILE=/etc/vpn-kit/options

TOKEN=""; RU_BLOCK=1; RU_DNS=1; ADGUARD=1; AUTO_REBOOT=1; BOT=1; UNINSTALL=0; YES=0

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
  --uninstall         удалить VPN Server Kit (AmneziaWG и клиенты остаются)
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
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

CONFIG_PATH = os.environ.get("VPN_BOT_CONFIG", "/etc/vpn-bot/config.json")
KIT_OPTIONS = "/etc/vpn-kit/options"   # параметры установки (их учитывает повторный запуск установщика)
DATA_DIR = "/var/lib/vpn-bot"
CLIENTS_DIR = os.path.join(DATA_DIR, "clients")
BACKUP_DIR = os.path.join(DATA_DIR, "backup")

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
def run(cmd, inp=None, timeout=60):
    kw = {"input": inp} if inp is not None else {"stdin": subprocess.DEVNULL}
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


def read_file(path):
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


_uapi_pid = 0


def uapi_peers():
    """Состояние клиентов напрямую из управляющего сокета amneziawg-go (дёшево, без docker exec).
    -> {pub_base64: {"endpoint": "ip:port", "hs": unix_time}}"""
    global _uapi_pid
    buf = b""
    for attempt in range(2):
        if not _uapi_pid:
            rc, out, _ = run(["docker", "inspect", "-f", "{{.State.Pid}}", AWG_CONTAINER])
            _uapi_pid = int(out.strip() or 0) if rc == 0 else 0
        # в Alpine /var/run -> /run (абсолютная ссылка), поэтому путь через /run
        path = "/proc/%d/root/run/amneziawg/%s.sock" % (_uapi_pid, AWG_IF)
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
            _uapi_pid = 0
            buf = b""
            if attempt:
                raise
    peers, cur = {}, None
    for line in buf.decode(errors="replace").splitlines():
        k, _, v = line.partition("=")
        if k == "public_key":
            cur = {"endpoint": "", "hs": 0}
            peers[base64.b64encode(bytes.fromhex(v)).decode()] = cur
        elif cur is not None:
            if k == "endpoint":
                cur["endpoint"] = v
            elif k == "last_handshake_time_sec":
                cur["hs"] = int(v or 0)
    return peers


def conf_path(pub):
    return os.path.join(CLIENTS_DIR, pub.replace("/", "_").replace("+", "-").rstrip("=") + ".conf")


def get_clients():
    _, _, peers = awg_conf()
    table = {c.get("clientId"): c.get("userData", {}) for c in load_table()}
    dump = awg_dump()
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
                    "tx": d.get("tx", 0), "endpoint": d.get("endpoint", "(none)"),
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
    save_cfg()
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
    if pub in CFG.get("blocked", []) or pub in CFG.get("share_mute", {}):
        CFG["blocked"] = [p for p in CFG.get("blocked", []) if p != pub]
        CFG.get("share_mute", {}).pop(pub, None)
        save_cfg()
        write_blocked_file()


def qr_png(text):
    try:
        p = subprocess.run(["qrencode", "-t", "PNG", "-o", "-", "-s", "5", "-m", "2", "-l", "L"],
                           input=text.encode(), capture_output=True, timeout=20)
        return p.stdout if p.returncode == 0 and p.stdout else None
    except Exception:
        return None


# ====================== система ======================
def container_state(name):
    rc, out, _ = run(["docker", "inspect", "-f", "{{.State.Running}}|{{.State.StartedAt}}", name])
    if rc != 0:
        return (False, "absent")
    running, started = out.strip().split("|", 1)
    return (running == "true", started)


def cpu_percent():
    def snap():
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        return v[3] + v[4], sum(v)
    i1, t1 = snap()
    time.sleep(0.5)
    i2, t2 = snap()
    return 100.0 * (1 - (i2 - i1) / max(t2 - t1, 1))


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
           [btn("🇷🇺 Блокировка RU", "ru"), btn("⚙️ Сервис", "service")]]


def view_menu():
    return "<b>🛡 Панель VPN-сервера</b>\nВыберите раздел:", MAIN_KB


def ok_icon(b):
    return "🟢" if b else "🔴"


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
    return "\n".join(lines), [[btn("🔄 Обновить", "status")], BACK]


def view_clients():
    cl = get_clients()
    lines = ["<b>👥 Клиенты (%d)</b>" % len(cl), "🟢 онлайн · ⚪️ нет подключения последние 3 мин", ""]
    kb = []
    for c in cl:
        online = c["hs"] and time.time() - c["hs"] < ONLINE_SEC
        dot = "⛔" if is_blocked(c["pub"]) else "🟢" if online else "⚪️"
        if sum(len(x) for x in lines) < 3300:
            lines.append("%s <b>%s</b> · %s · %s · ⬇️%s ⬆️%s" % (
                dot, e(c["name"]), c["ip"], ago(c["hs"]), hb(c["tx"]), hb(c["rx"])))
        kb.append([btn("%s %s" % (dot, c["name"][:40]), "c:" + c["pub"])])
    if not cl:
        lines.append("Клиентов пока нет.")
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
    lines = ["<b>👤 %s</b>%s" % (e(c["name"]), "  ⛔ <b>ОТКЛЮЧЁН</b>" if blocked else ""),
             "IP в VPN: <code>%s</code>" % c["ip"],
             "Создан: %s" % e(c["created"] or "—"),
             "Последнее подключение: %s" % ago(c["hs"]),
             "Откуда: <code>%s</code>" % e(ep.rsplit(":", 1)[0]) if ep and ep != "(none)" else "Откуда: —",
             "Трафик (с запуска VPN): ⬇️ %s ⬆️ %s" % (hb(c["tx"]), hb(c["rx"])),
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


def view_service():
    text = ("<b>⚙️ Сервис</b>\n\n"
            "• Перезапуск VPN — клиенты переподключатся автоматически (~10 сек).\n"
            "• Перезагрузка сервера — VPN недоступен ~1 мин.")
    kb = [[btn("🔄 Перезапустить VPN", "ask:rvpn")],
          [btn("🔄 Перезапустить AdGuard", "ask:rag")],
          [btn("♻️ Перезагрузить сервер", "ask:reboot")],
          BACK]
    return text, kb


CONFIRM = {"rvpn": "Перезапустить контейнер VPN?",
           "rag": "Перезапустить AdGuard Home?",
           "reboot": "Перезагрузить сервер? VPN будет недоступен около минуты."}


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


def send_client_conf(chat, name, ip, conf, created=False):
    cap = ("✅ Клиент <b>%s</b> создан, IP %s\n\n" % (e(name), ip) if created else "📄 <b>%s</b>\n\n" % e(name)) + \
          ("Как подключиться: установите <b>AmneziaVPN</b> (или AmneziaWG) → «+» → "
           "«Файл с настройками» и выберите этот файл, либо отсканируйте QR-код ниже.")
    send_file(chat, conf_filename(name, ip), conf.encode(), cap)
    png = qr_png(conf)
    if png:
        send_photo(chat, png, "QR-код для «%s»" % e(name))


def handle_callback(cq):
    uid = cq["from"]["id"]
    data = cq.get("data", "")
    msg = cq.get("message") or {}
    chat, mid = msg.get("chat", {}).get("id"), msg.get("message_id")
    tg("answerCallbackQuery", {"callback_query_id": cq["id"]})
    if uid not in ADMINS or chat is None:
        return

    def show(view):
        edit(chat, mid, *view)

    def wait(text):
        edit(chat, mid, "⏳ " + text)

    try:
        if data == "menu":
            pending.pop(chat, None)
            show(view_menu())
        elif data == "status":
            show(view_status())
        elif data == "clients":
            show(view_clients())
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
            set_blocked(pub, True)
            show(view_client(pub))
        elif data.startswith("cunb:"):
            pub = data[5:]
            wait("Включаю…")
            set_blocked(pub, False)
            show(view_client(pub))
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
            delete_client(pub)
            ag_sync()
            send(chat, "✅ Клиент <b>%s</b> удалён." % e(c["name"] if c else pub))
            show(view_clients())
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
        elif data.startswith("ask:"):
            act = data[4:]
            back = "adguard" if act == "rag" else "service"
            show((CONFIRM.get(act, "Подтвердите действие"),
                  [[btn("✅ Да", "do:" + act), btn("❌ Отмена", back)]]))
        elif data == "do:rvpn":
            wait("Перезапускаю VPN…")
            rc, _, err = run(["docker", "restart", AWG_CONTAINER], timeout=120)
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


def handle_message(m):
    chat = m["chat"]["id"]
    uid = m.get("from", {}).get("id")
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
        else:
            send(chat, "⛔ Нет доступа.\nВаш Telegram ID: <code>%s</code>" % uid)
        return

    if pending.get(chat) == "add_name" and text and not text.startswith("/"):
        pending.pop(chat, None)
        do_add(chat, text)
        return

    cmd = text.split()[0].split("@")[0].lower() if text else ""
    arg = text.split(maxsplit=1)[1] if len(text.split(maxsplit=1)) > 1 else ""
    try:
        if cmd == "/status":
            send(chat, *view_status())
        elif cmd == "/clients":
            send(chat, *view_clients())
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
                cl = get_clients()
                if seen is not None:
                    for c in cl:
                        if c["hs"] and not seen.get(c["pub"]):
                            alerts.append("🆕 Клиент <b>%s</b> подключился впервые" % e(c["name"]))
                seen = {c["pub"]: bool(c["hs"]) or (seen or {}).get(c["pub"], False) for c in cl}
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
                                  "allowed_updates": ["message", "callback_query"]}, timeout=70)
            if not r.get("ok"):
                log("getUpdates:", r.get("description"))
                time.sleep(10)
                continue
            for u in r["result"]:
                offset = u["update_id"] + 1
                try:
                    if "callback_query" in u:
                        handle_callback(u["callback_query"])
                    elif "message" in u:
                        handle_message(u["message"])
                except Exception:
                    log("update:", traceback.format_exc())
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
# VPN Server Kit: параметры установки. Повторный запуск установщика их учитывает,
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
    qrencode python3 iproute2 util-linux >/tmp/vpnkit-apt.log 2>&1 \
    || { tail -15 /tmp/vpnkit-apt.log; die "Не удалось установить пакеты"; }
  ok "ipset, ufw, fail2ban, unattended-upgrades, qrencode"
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
// VPN Server Kit: перезагрузка, если обновление ядра/библиотек её требует — ночью
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
  say "Готово (VPN Server Kit $KIT_VERSION)"
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
  say "Удаление VPN Server Kit"
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
  say "VPN Server Kit удалён"
  echo "   ufw, fail2ban, автообновления и BBR остались. Отключить межсетевой экран: ufw disable"
  echo
}

if [ "$UNINSTALL" = 1 ]; then
  uninstall
  exit 0
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
