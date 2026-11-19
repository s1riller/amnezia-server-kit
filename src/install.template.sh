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
KIT_VERSION="1.3.1"
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
  --uninstall         удалить VPN Server Kit (AmneziaWG и клиенты остаются)
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

#@@FILES@@

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
  [ -d "$tmp/etc/vpn-bot" ] || { rm -rf "$tmp"; die "В архиве нет данных бота — это не бэкап VPN Server Kit"; }
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
