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
        self.patch("TRAFFIC_PATH", os.path.join(self.tmp, "traffic.json"))
        bot.CFG.pop("blocked", None)
        bot.CFG.pop("share_mute", None)
        bot.CFG.pop("clients", None)
        bot.CFG.pop("requests", None)
        bot.CFG.pop("tariffs", None)
        bot.CFG.pop("payments", None)

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

    def test_rekey_carries_expiry_limit_and_traffic(self):
        bot.CFG.setdefault("clients", {})["AAAA"] = {"expires": "2030-01-01", "limit_gb": 50}
        bot.save_traffic({"AAAA": {"month": bot.cur_month(), "rx": 100, "tx": 200,
                                   "last_rx": 100, "last_tx": 200}})
        bot.rekey_client("AAAA")
        self.assertNotIn("AAAA", bot.CFG["clients"])
        self.assertEqual(bot.CFG["clients"]["NEW1"]["limit_gb"], 50)
        tr = bot.load_traffic()
        self.assertNotIn("AAAA", tr)
        self.assertEqual(tr["NEW1"]["rx"], 100)

    def test_delete_clears_client_data_and_traffic(self):
        bot.CFG.setdefault("clients", {})["AAAA"] = {"limit_gb": 10}
        bot.save_traffic({"AAAA": {"month": bot.cur_month(), "rx": 1, "tx": 2,
                                   "last_rx": 1, "last_tx": 2}})
        bot.delete_client("AAAA")
        self.assertNotIn("AAAA", bot.CFG.get("clients", {}))
        self.assertNotIn("AAAA", bot.load_traffic())


class RequestsTest(FakeAwg):
    def setUp(self):
        super().setUp()
        self.patch("ag_sync", lambda: None)
        self.sent = []
        self.patch("send", lambda *a, **k: self.sent.append(a))
        self.patch("send_file", lambda *a, **k: None)
        self.patch("send_photo", lambda *a, **k: None)
        bot.CFG.pop("requests", None)

    def test_add_request_antispam(self):
        self.assertTrue(bot.add_request(555, "Bob", "bob"))     # первая — принята
        self.assertFalse(bot.add_request(555, "Bob", "bob"))    # свежая — админа не спамим
        self.assertIn("555", bot.CFG["requests"])

    def test_client_owned_by(self):
        bot.set_cdata("AAAA", owner=777)
        c = bot.client_owned_by(777)
        self.assertIsNotNone(c)
        self.assertEqual(c["pub"], "AAAA")
        self.assertIsNone(bot.client_owned_by(888))

    def test_do_approve_creates_owned_client_with_limits(self):
        bot.CFG.setdefault("requests", {})["999"] = {"name": "Alice", "username": "alice", "ts": 0}
        name, ip = bot.do_approve(999, 30, 50)
        self.assertEqual(name, "Alice")
        c = bot.client_owned_by(999)
        self.assertIsNotNone(c)
        cd = bot.cdata(c["pub"])
        self.assertEqual(cd["owner"], 999)
        self.assertEqual(cd["limit_gb"], 50)
        self.assertGreater(cd["expires"], bot.today_str())
        self.assertNotIn("999", bot.CFG.get("requests", {}))   # заявка снята

    def test_do_approve_unlimited(self):
        bot.CFG.setdefault("requests", {})["1000"] = {"name": "Bob", "username": "", "ts": 0}
        bot.do_approve(1000, 0, 0)
        cd = bot.cdata(bot.client_owned_by(1000)["pub"])
        self.assertNotIn("expires", cd)
        self.assertNotIn("limit_gb", cd)

    def test_backup_pass_view_and_set(self):
        bot.CFG.pop("backup_pass", None)
        p1, new = bot.backup_passphrase()           # создаётся при первом обращении
        self.assertTrue(new and p1)
        p2, new2 = bot.backup_passphrase()          # повторно — тот же, не новый
        self.assertEqual(p1, p2)
        self.assertFalse(new2)
        self.assertEqual(bot.set_backup_pass("my-secret-123"), "my-secret-123")
        self.assertEqual(bot.CFG["backup_pass"], "my-secret-123")
        gen = bot.set_backup_pass("")               # пустой -> случайный
        self.assertTrue(gen and gen != "my-secret-123")
        bot.CFG.pop("backup_pass", None)


class PaymentsTest(FakeAwg):
    def setUp(self):
        super().setUp()
        for fn in ("ag_sync", "send", "send_file", "send_photo", "notify_admins"):
            self.patch(fn, (lambda *a, **k: None))

    def test_tariffs_seeded(self):
        ts = bot.tariffs()
        self.assertTrue(ts and all("id" in t and "stars" in t for t in ts))
        self.assertIsNotNone(bot.tariff_by_id(ts[0]["id"]))
        self.assertTrue(bot.tariffs_enabled())

    def test_purchase_new_user_creates_client(self):
        t = {"id": "x", "label": "30д", "stars": 100, "days": 30, "gb": 50, "on": True}
        bot.apply_purchase(999, t, charge_id="ch1", stars=100)
        c = bot.client_owned_by(999)
        self.assertIsNotNone(c)
        cd = bot.cdata(c["pub"])
        self.assertEqual(cd["owner"], 999)
        self.assertEqual(cd["limit_gb"], 50)
        self.assertGreater(cd["expires"], bot.today_str())
        pay = bot.CFG["payments"][-1]
        self.assertEqual((pay["charge_id"], pay["uid"], pay["stars"]), ("ch1", 999, 100))

    def test_purchase_existing_extends_and_unlimited(self):
        bot.set_cdata("AAAA", owner=777, expires="2030-01-01")
        t = {"id": "x", "label": "+30", "stars": 50, "days": 30, "gb": 0, "on": True}
        bot.apply_purchase(777, t, charge_id="ch2", stars=50)
        cd = bot.cdata("AAAA")
        self.assertEqual(cd["expires"], "2030-01-31")   # +30 дней от текущего срока
        self.assertNotIn("limit_gb", cd)                # gb=0 -> без лимита


class CanaryTest(FakeAwg):
    def setUp(self):
        super().setUp()
        self.patch("ag_sync", lambda: None)

    def test_install_cmd(self):
        bot.CFG["token"] = "TOK123"
        bot.CFG["server_name"] = "Berlin"
        try:
            cmd = bot.canary_install_cmd(777)
        finally:
            bot.CFG.pop("token", None); bot.CFG.pop("server_name", None)
        self.assertIn("install-canary.sh", cmd)
        self.assertIn("--token TOK123", cmd)
        self.assertIn("--chat 777", cmd)
        self.assertIn("--label 'Berlin'", cmd)
        b64 = cmd.split("--conf-b64 ", 1)[1].strip()
        import base64 as _b
        self.assertIn("[Interface]", _b.b64decode(b64).decode())

    def test_canary_client_reused(self):
        bot.ag_sync = lambda: None
        bot.canary_install_cmd(1)                      # создаёт клиента canary
        n1 = sum(1 for c in bot.get_clients() if c["name"] == bot.CANARY_NAME)
        bot.canary_install_cmd(1)                      # повторно — не плодит новых
        n2 = sum(1 for c in bot.get_clients() if c["name"] == bot.CANARY_NAME)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 1)


class TrafficTest(unittest.TestCase):
    def test_account_delta_normal(self):
        self.assertEqual(bot.account_delta(100, 250), 150)
        self.assertEqual(bot.account_delta(0, 0), 0)

    def test_account_delta_counter_reset(self):
        # счётчик обнулился (перезапуск контейнера): cur < prev -> прирост = cur
        self.assertEqual(bot.account_delta(5000, 30), 30)

    def test_roll_month_first_reading_starts_at_zero(self):
        e = bot.roll_month(None, "2026-11", 1000, 2000)
        self.assertEqual((e["rx"], e["tx"]), (0, 0))
        self.assertEqual((e["last_rx"], e["last_tx"]), (1000, 2000))

    def test_roll_month_accumulates(self):
        e = bot.roll_month(None, "2026-11", 1000, 2000)
        e = bot.roll_month(e, "2026-11", 1500, 2500)
        self.assertEqual((e["rx"], e["tx"]), (500, 500))
        e = bot.roll_month(e, "2026-11", 1600, 2600)
        self.assertEqual((e["rx"], e["tx"]), (600, 600))

    def test_roll_month_handles_reset(self):
        e = {"month": "2026-11", "rx": 500, "tx": 500, "last_rx": 1500, "last_tx": 2500}
        e = bot.roll_month(e, "2026-11", 40, 60)   # контейнер перезапущен, счётчики с нуля
        self.assertEqual((e["rx"], e["tx"]), (540, 560))

    def test_roll_month_new_month_resets(self):
        e = {"month": "2026-11", "rx": 999, "tx": 999, "last_rx": 10, "last_tx": 10}
        e = bot.roll_month(e, "2026-12", 10, 10)
        self.assertEqual((e["rx"], e["tx"]), (0, 0))


class DateTest(unittest.TestCase):
    def test_parse_date_formats(self):
        self.assertEqual(bot.parse_date("2026-12-31"), "2026-12-31")
        self.assertEqual(bot.parse_date("31.12.2026"), "2026-12-31")
        self.assertEqual(bot.parse_date("01.02.27"), "2027-02-01")

    def test_parse_date_relative(self):
        import time as _t
        want = _t.strftime("%Y-%m-%d", _t.localtime(_t.time() + 30 * 86400))
        self.assertEqual(bot.parse_date("+30"), want)

    def test_parse_date_invalid(self):
        for bad in ("завтра", "32.13.2026", "", "-5"):
            with self.assertRaises(ValueError):
                bot.parse_date(bad)


class AccessLogicTest(unittest.TestCase):
    def test_is_expired(self):
        self.assertTrue(bot.is_expired({"expires": "2000-01-01"}))
        self.assertFalse(bot.is_expired({"expires": "2999-01-01"}))
        self.assertFalse(bot.is_expired({}))

    def test_is_over_limit(self):
        self.assertTrue(bot.is_over_limit({"limit_gb": 1}, 2 * bot.GB))
        self.assertFalse(bot.is_over_limit({"limit_gb": 10}, 2 * bot.GB))
        self.assertFalse(bot.is_over_limit({}, 999 * bot.GB))


class TrafficAnalyzerTest(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(bot.byte_entropy(b""), 0.0)
        self.assertEqual(bot.byte_entropy(b"\x00" * 100), 0.0)          # один байт — нулевая энтропия
        self.assertAlmostEqual(bot.byte_entropy(bytes(range(256))), 8.0, places=6)  # равномерно — 8
        self.assertLess(bot.byte_entropy(b"GET / HTTP/1.1\r\n" * 10), 6.0)          # текст — низкая

    def test_classify_header(self):
        self.assertEqual(bot.classify_header(b"\x01\x00\x00\x00abcd"), "wg")   # ванильный WireGuard
        self.assertEqual(bot.classify_header(b"\x16\x03\x01\x00"), "tls")
        self.assertEqual(bot.classify_header(b"\xc3\xff\xff"), "quic")
        self.assertEqual(bot.classify_header(b"\x17\x9a\x2b\x4c"), "other")     # обфусцированный
        self.assertEqual(bot.classify_header(b""), "other")


class BlockDetectTest(unittest.TestCase):
    def test_block_suspected_true(self):
        # сервер в сети, пик активных был >=3, сейчас 0, прошло >3 мин после перезапуска
        self.assertTrue(bot.block_suspected(0, 5, True, 600))

    def test_not_when_clients_active(self):
        self.assertFalse(bot.block_suspected(2, 5, True, 600))

    def test_not_when_low_peak(self):
        self.assertFalse(bot.block_suspected(0, 2, True, 600))

    def test_not_when_egress_down(self):
        self.assertFalse(bot.block_suspected(0, 5, False, 600))   # это проблема сервера, не блокировка

    def test_not_right_after_restart(self):
        self.assertFalse(bot.block_suspected(0, 5, True, 60))


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


CLIENT_CONF = """[Interface]
PrivateKey = cPRIVKEY
Address = 10.8.1.2/32
DNS = 1.1.1.1, 1.0.0.1
MTU = 1376
Jc = 6
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = xEX1Pjj+SNmQxXO3kr1YPsyCbPkvwYn7Xg/x4JrJ0Zw=
RekeyAfterTime = 100-120
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = sPUBKEY
PresharedKey = PSKKEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
"""


class VpnUriTest(unittest.TestCase):
    def test_roundtrip_and_server_name(self):
        uri = bot.build_vpn_uri(CLIENT_CONF, "Мой сервер")
        self.assertTrue(uri.startswith("vpn://"))
        o = bot.decode_vpn_uri(uri)
        self.assertEqual(o["description"], "Мой сервер")        # имя, видимое пользователю
        self.assertEqual(o["defaultContainer"], "amnezia-awg")
        self.assertEqual(o["hostName"], "203.0.113.5")
        awg = o["containers"][0]["awg"]
        self.assertEqual(o["containers"][0]["container"], "amnezia-awg")
        self.assertEqual(awg["transport_proto"], "udp")
        self.assertEqual(awg["port"], "51820")
        self.assertEqual(o["format_version"], 1)
        last = json.loads(awg["last_config"])
        self.assertEqual(last["client_ip"], "10.8.1.2/32")
        self.assertEqual(last["client_priv_key"], "cPRIVKEY")
        self.assertEqual(last["server_pub_key"], "sPUBKEY")
        self.assertEqual(last["psk_key"], "PSKKEY")
        self.assertEqual(last["port"], 51820)
        self.assertEqual(last["H1"], "1")
        self.assertEqual(last["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertIn("[Interface]", last["config"])
        # все параметры AmneziaWG 2.0 из [Interface] должны быть отдельными полями
        for k, v in (("S3", "12"), ("S4", "12"), ("HeaderProtectionKey", "xEX1Pjj+SNmQxXO3kr1YPsyCbPkvwYn7Xg/x4JrJ0Zw="),
                     ("RekeyAfterTime", "100-120"), ("RandomTrailers", "on"), ("DisableCookies", "on")):
            self.assertEqual(last[k], v)
        # базовые WG-ключи не дублируются отдельными полями
        for k in ("PrivateKey", "Address", "DNS", "MTU"):
            self.assertNotIn(k, last)

    def test_length_prefix(self):
        import struct as _s, base64 as _b, zlib as _z
        uri = bot.build_vpn_uri(CLIENT_CONF, "x")
        raw = uri[6:] + "=" * (-len(uri[6:]) % 4)
        blob = _b.urlsafe_b64decode(raw)
        self.assertEqual(_s.unpack(">I", blob[:4])[0], len(_z.decompress(blob[4:])))

    def test_srv_name_default(self):
        bot.CFG.pop("server_name", None)
        self.assertEqual(bot.srv_name(), "AmneziaWG")
        bot.CFG["server_name"] = "   "
        self.assertEqual(bot.srv_name(), "AmneziaWG")
        bot.CFG["server_name"] = "Berlin-1"
        self.assertEqual(bot.srv_name(), "Berlin-1")
        bot.CFG.pop("server_name", None)


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
