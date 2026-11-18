"""Тесты bot.py без Docker и Telegram: файлы контейнера AmneziaWG подменяются словарём в памяти.

Запуск (Linux, из корня репозитория):  python3 -m unittest discover -s tests -v
"""
import importlib.util
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True   # не оставлять src/__pycache__
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_tmp_cfg_dir = tempfile.mkdtemp(prefix="vpnbot-test-")
os.environ["VPN_BOT_CONFIG"] = os.path.join(_tmp_cfg_dir, "config.json")
with open(os.environ["VPN_BOT_CONFIG"], "w", encoding="utf-8") as f:
    json.dump({"token": "", "admins": [1], "setup_code": "x"}, f)

_spec = importlib.util.spec_from_file_location("bot", os.path.join(ROOT, "src", "bot.py"))
bot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bot)

SERVER_CONF = """[Interface]
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LXNlcnZlci1wcml2YXQ=
Address = 10.8.1.0/24
ListenPort = 51820
Jc = 4
Jmin = 10
Jmax = 50
S1 = 58
S2 = 106
H1 = 1111
H2 = 2222
H3 = 3333
H4 = 4444
PostUp = iptables -A FORWARD -i awg0 -j ACCEPT

[Peer]
PublicKey = AAAA
PresharedKey = PSK
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = BBBB
PresharedKey = PSK
AllowedIPs = 10.8.1.3/32
"""


class FakeAwg(unittest.TestCase):
    """Общая подготовка: «контейнер» в памяти, временные каталоги вместо /var/lib/vpn-bot."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpnbot-")
        self.fs = {
            bot.AWG_CONF: SERVER_CONF,
            bot.AWG_TABLE: json.dumps([
                {"clientId": "AAAA", "userData": {"clientName": "Мама", "allowed_ips": "10.8.1.1/32"}},
                {"clientId": "BBBB", "userData": {"clientName": "Папа", "allowed_ips": "10.8.1.3/32"}}]),
            bot.AWG_PSK: "PSK\n",
            bot.AWG_SERVER_PUB: "SERVERPUB\n",
        }
        self.awg_cmds = []
        self.keys = iter([("PRIV1", "NEW1"), ("PRIV2", "NEW2")])
        self._saved = {}
        self.patch("read_file", self.fake_read)
        self.patch("write_file", self.fake_write)
        self.patch("dexec", self.fake_dexec)
        self.patch("gen_keys", lambda: next(self.keys))
        self.patch("server_ip", lambda: "203.0.113.5")
        self.patch("CLIENTS_DIR", os.path.join(self.tmp, "clients"))
        self.patch("BACKUP_DIR", os.path.join(self.tmp, "backup"))
        self.patch("BLOCKED_FILE", os.path.join(self.tmp, "blocked-ips.txt"))
        self.patch("AG_STATE", os.path.join(self.tmp, "adguard-clients.json"))
        self.patch("AG_LOCK", os.path.join(self.tmp, "adguard.lock"))
        self.patch("KIT_OPTIONS", os.path.join(self.tmp, "options"))
        bot.CFG.pop("blocked", None)
        bot.CFG.pop("share_mute", None)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(bot, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def patch(self, name, value):
        self._saved.setdefault(name, getattr(bot, name))
        setattr(bot, name, value)

    def fake_read(self, path):
        if path not in self.fs:
            raise RuntimeError("нет файла " + path)
        return self.fs[path]

    def fake_write(self, path, content):
        self.fs[path] = content

    def fake_dexec(self, *args, inp=None, timeout=30):
        self.awg_cmds.append(args)
        return 0, "", ""

    def peers(self):
        return {p["PublicKey"]: p for p in bot.awg_conf()[2]}


class ParseTest(FakeAwg):
    def test_awg_conf(self):
        _, iface, peers = bot.awg_conf()
        self.assertEqual(dict(iface)["ListenPort"], "51820")
        self.assertEqual([p["PublicKey"] for p in peers], ["AAAA", "BBBB"])
        self.assertEqual(bot.peer_ip(peers[1]), "10.8.1.3")

    def test_split_blocks_roundtrip(self):
        self.assertEqual("".join(bot.split_blocks(SERVER_CONF)), SERVER_CONF)

    def test_block_items_skips_comments(self):
        items = bot.block_items("[Peer]\n# comment = no\nPublicKey = X=\n\nAllowedIPs = 10.0.0.2/32\n")
        self.assertEqual(items, [("PublicKey", "X="), ("AllowedIPs", "10.0.0.2/32")])


class ClientOpsTest(FakeAwg):
    def test_create_takes_first_free_ip(self):
        r = bot.create_client("Сын")
        self.assertEqual(r["ip"], "10.8.1.2")             # .0 — сервер, .1 и .3 заняты
        self.assertEqual(self.peers()["NEW1"]["AllowedIPs"], "10.8.1.2/32")
        table = json.loads(self.fs[bot.AWG_TABLE])
        self.assertEqual(table[-1]["clientId"], "NEW1")
        self.assertEqual(table[-1]["userData"]["clientName"], "Сын")
        self.assertIn(("awg", "set", "awg0", "peer", "NEW1", "preshared-key", bot.AWG_PSK,
                       "allowed-ips", "10.8.1.2/32"), self.awg_cmds)
        self.assertTrue(os.path.exists(bot.conf_path("NEW1")))
        self.assertTrue(os.listdir(bot.BACKUP_DIR), "перед изменением должна быть резервная копия")

    def test_create_second_client_gets_next_ip(self):
        bot.create_client("A")
        self.assertEqual(bot.create_client("B")["ip"], "10.8.1.4")

    def test_create_fails_when_subnet_full(self):
        self.fs[bot.AWG_CONF] = SERVER_CONF.replace("Address = 10.8.1.0/24", "Address = 10.8.1.0/30") \
            .replace("10.8.1.3/32", "10.8.1.2/32")
        with self.assertRaises(RuntimeError):
            bot.create_client("X")

    def test_rekey_changes_only_target_peer(self):
        r = bot.rekey_client("AAAA")
        peers = self.peers()
        self.assertNotIn("AAAA", peers)
        self.assertEqual(peers["NEW1"]["AllowedIPs"], "10.8.1.1/32")
        self.assertEqual(peers["BBBB"]["AllowedIPs"], "10.8.1.3/32")
        self.assertEqual(r["ip"], "10.8.1.1")
        ids = [t["clientId"] for t in json.loads(self.fs[bot.AWG_TABLE])]
        self.assertEqual(ids, ["NEW1", "BBBB"])
        self.assertIn(("awg", "set", "awg0", "peer", "AAAA", "remove"), self.awg_cmds)

    def test_rekey_blocked_client_stays_blocked(self):
        bot.CFG["blocked"] = ["AAAA"]
        bot.rekey_client("AAAA")
        self.assertEqual(bot.CFG["blocked"], ["NEW1"])
        self.assertFalse(any(c[:5] == ("awg", "set", "awg0", "peer", "NEW1") for c in self.awg_cmds),
                         "отключённый клиент не должен попасть в живой интерфейс")

    def test_delete_removes_only_target(self):
        bot.delete_client("AAAA")
        self.assertEqual(list(self.peers()), ["BBBB"])
        self.assertEqual([t["clientId"] for t in json.loads(self.fs[bot.AWG_TABLE])], ["BBBB"])

    def test_delete_unknown_raises(self):
        with self.assertRaises(RuntimeError):
            bot.delete_client("ZZZZ")


class ClientConfTest(unittest.TestCase):
    def test_build_client_conf(self):
        iface = bot.block_items(bot.split_blocks(SERVER_CONF)[0])
        orig = bot.server_ip
        bot.server_ip = lambda: "203.0.113.5"
        try:
            text = bot.build_client_conf("PRIV", "10.8.1.7", iface, "SPUB", "PSK")
        finally:
            bot.server_ip = orig
        self.assertIn("Address = 10.8.1.7/32", text)
        self.assertIn("Endpoint = 203.0.113.5:51820", text)
        self.assertIn("Jc = 4", text)
        self.assertIn("H4 = 4444", text)
        for server_only in ("ListenPort", "PostUp", "c2VydmVy"):
            self.assertNotIn(server_only, text)

    def test_conf_filename(self):
        self.assertEqual(bot.conf_filename("Мама iPhone", "10.8.1.2"), "awg-mamaiPhone.conf")
        self.assertEqual(bot.conf_filename("!!!", "10.8.1.42"), "awg-42.conf")
        name = bot.conf_filename("Очень длинное имя клиента", "10.8.1.2")
        self.assertLessEqual(len(name) - len(".conf"), 15)   # имя туннеля WireGuard — до 15 символов


class ShareDetectorTest(unittest.TestCase):
    """Пороги из эксперимента в README: 1 устройство — 0 смен / 3 рукопожатия; 2 устройства — от 4 / 10."""

    def test_single_device(self):
        self.assertFalse(bot.share_suspected(1, 0, 3))
        self.assertFalse(bot.share_suspected(2, 1, 3))    # одна смена сети (Wi-Fi -> LTE)

    def test_two_devices(self):
        self.assertTrue(bot.share_suspected(2, 4, 10))
        self.assertTrue(bot.share_suspected(3, 38, 14))

    def test_many_changes_without_handshakes(self):
        self.assertTrue(bot.share_suspected(2, 10, 0))
        self.assertFalse(bot.share_suspected(2, 9, 0))

    def test_one_endpoint_never(self):
        self.assertFalse(bot.share_suspected(1, 50, 50))


class SplitFileTest(unittest.TestCase):
    def test_ru_list_and_local_nets(self):
        tmp = tempfile.mkdtemp()
        orig = bot.RU_CACHE
        bot.RU_CACHE = os.path.join(tmp, "ru_v4.txt")
        try:
            with open(bot.RU_CACHE, "w") as f:
                f.write("5.3.0.0/16\n5.3.1.0/24\n95.24.0.0/14\n")
            data, n = bot.split_file()
        finally:
            bot.RU_CACHE = orig
            shutil.rmtree(tmp)
        nets = [ipaddress.ip_network(x["hostname"]) for x in json.loads(data)]
        self.assertEqual(n, len(nets))

        def covered(ip):
            return any(ipaddress.ip_address(ip) in net for net in nets)

        self.assertTrue(covered("5.3.1.1"))
        self.assertTrue(covered("10.1.2.3"))
        self.assertTrue(covered("172.29.173.1"))
        self.assertFalse(covered("172.29.172.253"), "AdGuard должен оставаться в VPN")
        self.assertFalse(covered("8.8.8.8"))

    def test_empty_list_raises(self):
        orig = bot.RU_CACHE
        bot.RU_CACHE = "/nonexistent/ru.txt"
        try:
            with self.assertRaises(RuntimeError):
                bot.split_file()
        finally:
            bot.RU_CACHE = orig


class KitOptionsTest(FakeAwg):
    def test_set_kit_option(self):
        with open(bot.KIT_OPTIONS, "w") as f:
            f.write("# comment\nKIT_VERSION=1.1\nRU_BLOCK=1\nRU_DNS=1\n")
        bot.set_kit_option("RU_BLOCK", 0)
        bot.set_kit_option("NEW", 1)
        with open(bot.KIT_OPTIONS) as f:
            self.assertEqual(f.read(), "# comment\nKIT_VERSION=1.1\nRU_BLOCK=0\nRU_DNS=1\nNEW=1\n")

    def test_missing_options_file_is_ignored(self):
        bot.set_kit_option("RU_BLOCK", 0)
        self.assertFalse(os.path.exists(bot.KIT_OPTIONS))


class FormatTest(unittest.TestCase):
    def test_hb(self):
        self.assertEqual(bot.hb(0), "0 Б")
        self.assertEqual(bot.hb(1536), "1.5 КБ")
        self.assertEqual(bot.hb(3 * 1024 ** 3), "3.0 ГБ")

    def test_dur(self):
        self.assertEqual(bot.dur(59), "0 мин")
        self.assertEqual(bot.dur(3 * 3600 + 120), "3 ч 2 мин")
        self.assertEqual(bot.dur(2 * 86400 + 5 * 3600), "2 д 5 ч")


if __name__ == "__main__":
    unittest.main()
