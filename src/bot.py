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
            "Ежедневный отчёт: <b>%s</b>\n\n"
            "• Перезапуск VPN — клиенты переподключатся автоматически (~10 сек).\n"
            "• Перезагрузка сервера — VPN недоступен ~1 мин." % (
                e(str(ver)), ("\n⬆️ Доступна версия <b>%s</b>" % e(str(nv)) if nv else ""), REPORT_LABELS[mode]))
    kb = [[btn("💾 Бэкап в Telegram", "backup")],
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
        elif data == "reptgl":
            order = ["daily", "weekly", "off"]
            cur = CFG.get("report", "daily")
            CFG["report"] = order[(order.index(cur) + 1) % 3]
            save_cfg()
            show(view_service())
        elif data == "backup":
            do_backup(chat)
            show(view_service())
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

    pend = pending.get(chat, "")
    if pend.startswith(("exp:", "lim:")) and text and not text.startswith("/"):
        pending.pop(chat, None)
        do_set_limit(chat, pend[:3], pend[4:], text)
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
    last_report = today_str()   # при старте не слать отчёт за «сегодня»
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
                check_access(account_traffic())   # сроки и лимиты
                cl = get_clients()
                if seen is not None:
                    for c in cl:
                        if c["hs"] and not seen.get(c["pub"]):
                            alerts.append("🆕 Клиент <b>%s</b> подключился впервые" % e(c["name"]))
                seen = {c["pub"]: bool(c["hs"]) or (seen or {}).get(c["pub"], False) for c in cl}

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
