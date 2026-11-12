#!/usr/bin/env python3
"""
Собирает один самодостаточный установщик install-vpn-kit.sh
из шаблона install.template.sh и файлов в этой папке.

    python build.py [путь_к_результату]     (по умолчанию ../install-vpn-kit.sh)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "install-vpn-kit.sh")

# функция-в-установщике, путь на сервере, права, исходник
FILES = [
    ("file_block_ru_sh",          "/usr/local/sbin/block-ru.sh",          "755", "block-ru.sh"),
    ("file_block_ru_service",     "/etc/systemd/system/block-ru.service", "644", "block-ru.service"),
    ("file_block_ru_timer",       "/etc/systemd/system/block-ru.timer",   "644", "block-ru.timer"),
    ("file_vpn_net_sh",           "/usr/local/sbin/vpn-net.sh",           "755", "vpn-net.sh"),
    ("file_vpn_net_service",      "/etc/systemd/system/vpn-net.service",  "644", "vpn-net.service"),
    ("file_vpn_net_timer",        "/etc/systemd/system/vpn-net.timer",    "644", "vpn-net.timer"),
    ("file_adguard_sync_clients", "/usr/local/sbin/adguard-sync-clients", "700", "adguard-sync-clients"),
    ("file_bot_py",               "/opt/vpn-bot/bot.py",                  "644", "bot.py"),
    ("file_vpn_bot_service",      "/etc/systemd/system/vpn-bot.service",  "644", "vpn-bot.service"),
    ("file_vpn_bot_token",        "/usr/local/sbin/vpn-bot-token",        "755", "vpn-bot-token"),
]


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def main():
    tpl = read("install.template.sh")
    marker = "#@@FILES@@\n"
    if marker not in tpl:
        sys.exit("в шаблоне нет метки #@@FILES@@")
    parts = ["# ---------------- встроенные файлы (сгенерировано build.py) ----------------\n"]
    for fn, dst, mode, src in FILES:
        body = read(src)
        delim = "VPNKIT_EOF_" + fn.upper()
        if delim in body.splitlines():
            sys.exit("в %s встречается разделитель %s" % (src, delim))
        if not body.endswith("\n"):
            body += "\n"
        parts.append("%s() {\nput %s %s <<'%s'\n%s%s\n}\n\n" % (fn, dst, mode, delim, body, delim))
    out = tpl.replace(marker, "".join(parts), 1)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print("OK: %s (%d КБ, встроено файлов: %d)" % (os.path.abspath(OUT), len(out.encode()) // 1024, len(FILES)))


if __name__ == "__main__":
    main()
