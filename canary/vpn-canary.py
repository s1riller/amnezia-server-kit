#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN-канарейка: проверяет из сети российского провайдера, доступен ли ваш
AmneziaWG-сервер, и шлёт тревогу в Telegram при блокировке/восстановлении.

Запускается НЕ на сервере VPN, а на отдельном Linux-хосте В РОССИИ
(дешёвый VPS или домашний ПК/Raspberry Pi с root).

Как это работает:
  - раз в INTERVAL секунд поднимает туннель канареечного клиента только для
    теста (AllowedIPs=1.1.1.1/32 — трафик хоста не перехватывается),
  - дёргает 1.1.1.1 через туннель и смотрит, было ли рукопожатие,
  - гасит туннель и, если состояние сменилось (работает↔заблокирован),
    шлёт сообщение в Telegram напрямую (туннель к этому моменту опущен,
    поэтому Telegram доступен, даже если сервер заблокирован).

Настройка — через переменные окружения (см. canary/README.md):
  VPN_CANARY_TOKEN   токен Telegram-бота (можно тот же, что у серверного бота)
  VPN_CANARY_CHAT    ваш Telegram ID (куда слать тревоги)
  VPN_CANARY_CONF    путь к .conf канареечного клиента (из бота)
  VPN_CANARY_LABEL   метка этой точки, напр. "МТС Москва" (в тексте тревог)
  VPN_CANARY_INTERVAL   период проверки, сек (по умолчанию 300)
  VPN_CANARY_FAILS      сколько неудач подряд = «заблокирован» (по умолчанию 2)

Только стандартная библиотека Python. Нужны amneziawg-tools (awg, awg-quick).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request

TOKEN = os.environ.get("VPN_CANARY_TOKEN", "")
CHAT = os.environ.get("VPN_CANARY_CHAT", "")
CONF = os.environ.get("VPN_CANARY_CONF", "")
LABEL = os.environ.get("VPN_CANARY_LABEL", "канарейка")
INTERVAL = int(os.environ.get("VPN_CANARY_INTERVAL", "300"))
FAILS = int(os.environ.get("VPN_CANARY_FAILS", "2"))

IFACE = "awgcan"                     # имя тест-интерфейса (<=15 символов)
WORK_CONF = "/tmp/%s.conf" % IFACE
TEST_IP = "1.1.1.1"                  # куда ходим через туннель для проверки


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def tg(text):
    """Отправить сообщение в Telegram (вне туннеля)."""
    if not TOKEN or not CHAT:
        log("Telegram не настроен, пропускаю отправку:", text)
        return
    data = urllib.parse.urlencode({"chat_id": CHAT, "text": text,
                                   "disable_web_page_preview": "true"}).encode()
    try:
        urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % TOKEN, data=data, timeout=20)
    except Exception as ex:
        log("не удалось отправить в Telegram:", ex)


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except Exception as ex:
        return 1, "", str(ex)


def prepare_conf():
    """Скопировать .conf и сузить AllowedIPs до тест-IP, чтобы не перехватывать трафик хоста."""
    with open(CONF, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"(?mi)^\s*AllowedIPs\s*=.*$", "AllowedIPs = %s/32" % TEST_IP, text)
    with open(WORK_CONF, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(WORK_CONF, 0o600)


def tunnel_down():
    run(["awg-quick", "down", WORK_CONF], timeout=30)


def check():
    """Одна проверка. -> (ok: bool, detail: str). Туннель гарантированно опущен к выходу."""
    tunnel_down()  # на случай, если остался поднятым с прошлого раза
    rc, _, err = run(["awg-quick", "up", WORK_CONF], timeout=40)
    if rc != 0:
        tunnel_down()
        return False, "не удалось поднять туннель: %s" % (err.strip()[:200] or "awg-quick up")
    try:
        # дёргаем тест-IP через туннель, чтобы инициировать рукопожатие
        for _ in range(3):
            run(["curl", "--max-time", "6", "-s", "-o", "/dev/null", "https://%s" % TEST_IP], timeout=10)
            rc, out, _ = run(["awg", "show", IFACE, "latest-handshakes"], timeout=10)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    hs = int(parts[1])
                    if hs and time.time() - hs < 120:
                        return True, "рукопожатие есть"
            time.sleep(3)
        return False, "нет рукопожатия за отведённое время"
    finally:
        tunnel_down()


def main():
    for tool in ("awg", "awg-quick", "curl"):
        if not shutil.which(tool):
            log("не найден %s — установите amneziawg-tools и curl (см. README)" % tool)
            sys.exit(1)
    if not CONF or not os.path.exists(CONF):
        log("не задан/не найден VPN_CANARY_CONF:", CONF)
        sys.exit(1)
    prepare_conf()
    log("канарейка «%s» запущена, период %d сек" % (LABEL, INTERVAL))
    state = None          # None=неизвестно, True=работает, False=заблокирован
    fails = 0
    while True:
        try:
            ok, detail = check()
        except Exception as ex:
            ok, detail = False, "ошибка проверки: %s" % ex
        log("проверка:", "OK" if ok else "FAIL", "-", detail)
        if ok:
            if state is not True and fails >= FAILS:   # было «заблокирован» -> восстановилось
                tg("🟢 VPN снова доступен из сети «%s» (%s)." % (LABEL, detail))
            elif state is None:
                tg("🩺 Канарейка «%s»: VPN доступен." % LABEL)
            state = True
            fails = 0
        else:
            fails += 1
            if fails == FAILS and state is not False:   # подтверждённая блокировка
                tg("⛔ VPN НЕ доступен из сети «%s» (%d проверки подряд: %s). "
                   "Похоже, провайдер блокирует сервер." % (LABEL, fails, detail))
                state = False
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
