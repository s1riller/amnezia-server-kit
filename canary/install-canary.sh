#!/bin/bash
# =====================================================================
#  VPN Canary — установщик «канарейки» на хост В РОССИИ.
#
#  Ставит проверяльщик доступности вашего AmneziaWG-сервера и защищает
#  хост (ufw, fail2ban, автообновления, BBR) — как основной сервер.
#  Запускать на отдельном Linux-хосте в РФ (НЕ на сервере VPN), от root.
#
#  Пример:
#    bash install-canary.sh --token <токен> --chat <id> \
#         --label "МТС Москва" --conf-b64 <base64 .conf>
# =====================================================================
set -Eeuo pipefail
REPO="s1riller/amnezia-server-kit"
REL="https://github.com/$REPO/releases/latest/download"

TOKEN=""; CHAT=""; LABEL="канарейка"; INTERVAL="300"; CONF=""; CONF_B64=""; HARDEN=1

usage() { cat <<'EOF'
Использование: bash install-canary.sh [параметры]
  --token <токен>     токен Telegram-бота (можно тот же, что у серверного бота)
  --chat <id>         ваш Telegram ID (куда слать тревоги)
  --conf <файл>       .conf канареечного клиента (из бота)
  --conf-b64 <b64>    тот же .conf в base64 (для запуска одной строкой)
  --label <текст>     метка точки в тревогах, напр. "МТС Москва"
  --interval <сек>    период проверки (по умолчанию 300)
  --no-harden         не настраивать ufw/fail2ban/обновления/BBR
  -h, --help          справка
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)    TOKEN="${2:-}"; shift 2 ;;
    --chat)     CHAT="${2:-}"; shift 2 ;;
    --conf)     CONF="${2:-}"; shift 2 ;;
    --conf-b64) CONF_B64="${2:-}"; shift 2 ;;
    --label)    LABEL="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --no-harden) HARDEN=0; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1"; echo; usage; exit 1 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m✖ %s\033[0m\n' "$*" >&2; exit 1; }
trap 'die "Ошибка в строке $LINENO: $BASH_COMMAND"' ERR

[ "$(id -u)" = 0 ] || die "Запустите от root (sudo -i)"
command -v apt-get >/dev/null || die "Поддерживаются только Ubuntu/Debian"
[ -n "$TOKEN" ] || die "Не задан --token"
[ -n "$CHAT" ] || die "Не задан --chat (ваш Telegram ID)"
[ -n "$CONF$CONF_B64" ] || die "Не задан конфиг канарейки (--conf или --conf-b64)"

export DEBIAN_FRONTEND=noninteractive

install_base() {
  say "Установка пакетов"
  apt-get -o DPkg::Lock::Timeout=1800 update -q >/dev/null
  apt-get -o DPkg::Lock::Timeout=1800 install -y -q \
    curl ca-certificates python3 iproute2 iptables ufw fail2ban unattended-upgrades \
    software-properties-common gnupg2 >/tmp/canary-apt.log 2>&1 \
    || { tail -15 /tmp/canary-apt.log; die "Не удалось установить пакеты"; }
  ok "базовые пакеты"
}

install_amneziawg() {
  say "AmneziaWG (клиентские инструменты awg/awg-quick)"
  if command -v awg-quick >/dev/null && command -v awg >/dev/null; then
    ok "уже установлены"; return 0
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID:-}" = "ubuntu" ]; then
    apt-get install -y -q "linux-headers-$(uname -r)" python3-launchpadlib >>/tmp/canary-apt.log 2>&1 || true
    add-apt-repository -y ppa:amnezia/ppa >>/tmp/canary-apt.log 2>&1 || warn "не удалось добавить PPA"
    apt-get update -q >>/tmp/canary-apt.log 2>&1 || true
    apt-get install -y -q amneziawg >>/tmp/canary-apt.log 2>&1 || true
  else
    # Debian: репозиторий PPA вручную (ветка focal), ключ через signed-by
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x75C9DD72C799870E310542E24166F2C257290828" \
      | gpg --dearmor -o /etc/apt/keyrings/amnezia.gpg 2>>/tmp/canary-apt.log || warn "ключ PPA не добавлен"
    echo "deb [signed-by=/etc/apt/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" \
      > /etc/apt/sources.list.d/amnezia.list
    apt-get update -q >>/tmp/canary-apt.log 2>&1 || true
    apt-get install -y -q "linux-headers-$(uname -r)" amneziawg >>/tmp/canary-apt.log 2>&1 || true
  fi
  if command -v awg-quick >/dev/null; then
    ok "amneziawg установлен ($(awg --version 2>/dev/null | head -n1 || echo ok))"
  else
    warn "не удалось автоматически поставить amneziawg — см. /tmp/canary-apt.log и docs.amnezia.org;"
    warn "канарейка запустится, но проверка не заработает, пока нет awg/awg-quick"
  fi
}

harden() {
  [ "$HARDEN" = 1 ] || { ok "защита хоста пропущена (--no-harden)"; return 0; }
  say "Защита хоста (ufw, fail2ban, автообновления, BBR)"
  # SSH-порт(ы), чтобы не отрезать себе доступ
  local ports p
  ports=$( { echo "${SSH_CONNECTION:-}" | awk '{print $4}'
             sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
             ss -tlnpH 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print a[n]}'
           } | grep -E '^[0-9]+$' | sort -un || true)
  [ -n "$ports" ] || ports=22
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for p in $ports; do ufw allow "$p/tcp" comment 'SSH' >/dev/null; done
  ufw --force enable >/dev/null
  ok "ufw: разрешён только SSH ($(printf '%s\n' "$ports" | paste -sd, -)/tcp)"

  put_fail2ban
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || warn "fail2ban не запустился"
  ok "fail2ban: 5 неудач входа → бан на час"

  printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
    > /etc/apt/apt.conf.d/20auto-upgrades
  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
  ok "автообновления безопасности включены"

  echo tcp_bbr > /etc/modules-load.d/bbr.conf
  modprobe tcp_bbr 2>/dev/null || true
  printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' > /etc/sysctl.d/99-bbr.conf
  sysctl -q -p /etc/sysctl.d/99-bbr.conf 2>/dev/null || warn "BBR применится после перезагрузки"
  ok "BBR включён"
}

put_fail2ban() {
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd-local.conf <<'EOF'
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
}

install_canary() {
  say "Канарейка"
  mkdir -p /opt/vpn-canary
  if [ -n "$CONF_B64" ]; then
    echo "$CONF_B64" | base64 -d > /root/canary.conf || die "битый --conf-b64"
  else
    [ -f "$CONF" ] || die "файл не найден: $CONF"
    cp -f "$CONF" /root/canary.conf
  fi
  chmod 600 /root/canary.conf
  curl -fsSL "$REL/vpn-canary.py" -o /opt/vpn-canary/vpn-canary.py || die "не удалось скачать vpn-canary.py из релиза"
  python3 -m py_compile /opt/vpn-canary/vpn-canary.py || die "vpn-canary.py не компилируется"

  cat > /etc/systemd/system/vpn-canary.service <<EOF
[Unit]
Description=VPN canary (AmneziaWG reachability watchdog)
After=network-online.target
Wants=network-online.target

[Service]
Environment=VPN_CANARY_TOKEN=$TOKEN
Environment=VPN_CANARY_CHAT=$CHAT
Environment=VPN_CANARY_CONF=/root/canary.conf
Environment=VPN_CANARY_LABEL=$LABEL
Environment=VPN_CANARY_INTERVAL=$INTERVAL
ExecStart=/usr/bin/python3 /opt/vpn-canary/vpn-canary.py
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
  chmod 600 /etc/systemd/system/vpn-canary.service
  systemctl daemon-reload
  systemctl enable vpn-canary >/dev/null 2>&1
  systemctl restart vpn-canary
  sleep 2
  if systemctl is-active -q vpn-canary; then ok "канарейка «$LABEL» запущена"; else warn "служба не активна — см. journalctl -u vpn-canary"; fi
}

install_base
install_amneziawg
harden
install_canary
say "Готово"
echo "   Лог установки пакетов: /tmp/canary-apt.log"
echo "   Проверить канарейку:   journalctl -u vpn-canary -f"
echo
