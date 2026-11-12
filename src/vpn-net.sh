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
