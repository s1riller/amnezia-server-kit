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
