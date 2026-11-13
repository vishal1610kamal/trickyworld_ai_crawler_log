"""Tests for ai_crawl_report.py. Run from the project folder:  python3 -m unittest -v"""
import gzip
import io
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import ai_crawl_report as acr  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
RANGES = os.path.join(FIX, "ranges")
LOG = os.path.join(FIX, "sample_access.log")
SITEMAP = os.path.join(FIX, "sitemap.xml")

# User agents exactly as the operators document them (Chrome/W.X.Y.Z filled in with a real version).
DOCUMENTED = {
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/142.0.7444.59 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "Googlebot",
    "Googlebot-Image/1.0": "Googlebot",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GoogleOther) Chrome/142.0.7444.59 Safari/537.36":
        "GoogleOther",
    "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)": "Google-InspectionTool",
    "Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/142.0.7444.59 Safari/537.36": "Storebot-Google",
    "Google-CloudVertexBot": "Google-CloudVertexBot",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; compatible; Google-Agent; "
    "+https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent) Chrome/142.0.7444.59 Safari/537.36":
        "Google-Agent",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 "
    "(compatible; Google-GeminiNotebook; +https://developers.google.com/crawling/docs/crawlers-fetchers/"
    "google-gemininotebook)": "Google-GeminiNotebook",
    "Google-NotebookLM": "Google-GeminiNotebook",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/142.0.7444.59 Mobile Safari/537.36 (compatible; AdsBot-Google-Mobile; "
    "+http://www.google.com/mobile/adsbot.html)": "Google ads bots",
    "FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)": "Google fetchers (other)",
    "Google": "Google (Gemini)",
    "Google-Lens": "Google-Lens",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot": "GPTBot",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 "
    "Safari/537.36; compatible; OAI-SearchBot/1.4; +https://openai.com/searchbot": "OAI-SearchBot",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot":
        "ChatGPT-User",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-AdsBot/1.0; +https://openai.com/adsbot":
        "OAI-AdsBot",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-Agent/1.0) "
    "Chrome/154.0.0.0 Safari/537.36": "Claude-Agent",
    "Claude-User (claude-code/2.1.322; +https://support.anthropic.com/)": "Claude Code",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":
        "ClaudeBot",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)": "bingbot",
}


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def run_cli(*args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = acr.main(list(args))
    return code, buf.getvalue()


class Parsing(unittest.TestCase):
    def test_combined_line(self):
        hit = acr.parse_line('66.249.66.1 - - [12/Nov/2026:06:40:12 +0530] "GET /a/?x=1 HTTP/1.1" 200 51 "-" '
                             '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"')
        self.assertEqual((hit.ip, hit.method, hit.path, hit.query, hit.status), ("66.249.66.1", "GET", "/a/", "x=1", 200))
        self.assertEqual(hit.time, datetime(2026, 11, 12, 1, 10, 12, tzinfo=timezone.utc))
        self.assertEqual(hit.agent.name, "Googlebot")

    def test_vhost_combined_and_ipv6(self):
        hit = acr.parse_line('www.example.com:443 2001:db8::1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/2.0" '
                             '304 0 "-" "Google-Lens"')
        self.assertEqual((hit.ip, hit.status, hit.agent.name), ("2001:db8::1", 304, "Google-Lens"))

    def test_escaped_quotes_and_absolute_form(self):
        hit = acr.parse_line('192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET http://example.com/p?q=1 HTTP/1.1" '
                             '200 1 "-" "Mozilla/5.0 \\"quoted\\" ClaudeBot/1.0"')
        self.assertEqual((hit.path, hit.query, hit.ua), ("/p", "q=1", 'Mozilla/5.0 "quoted" ClaudeBot/1.0'))

    def test_rejects_garbage(self):
        self.assertIsNone(acr.parse_line("this is not a log line"))
        self.assertIsNone(acr.parse_line('1.2.3.4 - - [99/Foo/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'))

    def test_path_kinds(self):
        for path, kind in [("/robots.txt", "robots.txt"), ("/llms.txt", "llms.txt"), ("/llms-full.txt", "llms.txt"),
                           ("/sitemap_index.xml", "sitemap"), ("/post-sitemap-recent.xml", "sitemap"),
                           ("/feed/", "feed"), ("/_next/static/x.js", "asset"), ("/logo.webp", "asset"),
                           ("/computer-tricks/cyber-security/", "page")]:
            self.assertEqual(acr.path_kind(path), kind, path)


class Classify(unittest.TestCase):
    def test_documented_user_agents(self):
        for ua, name in DOCUMENTED.items():
            agent = acr.classify(ua)
            self.assertIsNotNone(agent, ua)
            self.assertEqual(agent.name, name, ua)

    def test_people_and_lookalikes_are_not_bots(self):
        for ua in ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/142.0.0.0 Safari/537.36", "Google Chrome", "GoogleBotanist/1.0", ""]:
            self.assertIsNone(acr.classify(ua), ua)

    def test_google_extended_in_a_user_agent_is_fake(self):
        self.assertEqual(acr.classify("Mozilla/5.0 (compatible; Google-Extended)").verdict, "fake")


class Ranges(unittest.TestCase):
    def test_loads_every_fixture(self):
        ranges = acr.load_ranges(RANGES)
        self.assertEqual(set(ranges), {"anthropic-bots", "anthropic-sail", "google-common", "google-special",
                                       "google-fetchers", "google-agents", "google-cloud-users", "openai-gptbot",
                                       "cloudflare"})
        self.assertEqual(ranges["anthropic-bots"]["created"], "2026-10-20T00:00:00Z")

    def test_sail_without_tomllib_matches_tomllib(self):
        text = read(os.path.join(RANGES, "anthropic-sail.toml"))
        mini = acr._mini_toml(text)
        nets = [str(n) for n in acr.parse_sail(text)[0]]
        self.assertIn("34.31.25.14/32", nets)
        self.assertEqual(len(nets), 9)
        self.assertEqual(mini["services"][0]["name"], "Claude-Agent")
        self.assertEqual(mini["expires_after"], 3600)
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+; the fallback parser was used above")
        full = tomllib.loads(text)
        self.assertEqual(mini["prefix_sets"][0]["ipv4_prefixes"], full["prefix_sets"][0]["ipv4_prefixes"])
        self.assertEqual(mini["services"], full["services"])

    def test_update_keeps_old_copy_when_a_download_fails(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        good = json.dumps({"creationTime": "x", "prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]})
        old = os.path.join(tmp, "openai-gptbot.json")
        with open(old, "w") as fh:
            fh.write(good)

        def fake_fetch(url, timeout=30):
            if "gptbot" in url:
                raise OSError("network down")
            if url.endswith("sail"):
                return read(os.path.join(RANGES, "anthropic-sail.toml"))
            if "cloudflare" in url:
                return "104.16.0.0/13\n"
            return good

        with mock.patch.object(acr, "fetch", fake_fetch), redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            failures = acr.update_ranges(tmp)
        self.assertEqual(failures, 1)
        self.assertIn("openai-gptbot", err.getvalue())
        self.assertEqual(read(old), good)
        self.assertEqual(len(acr.load_ranges(tmp)), len(acr.RANGE_SOURCES))


class Verification(unittest.TestCase):
    def setUp(self):
        self.ranges = acr.load_ranges(RANGES)

    def v(self, name, ip, dns=None):
        agent = next(a for a in acr.AGENTS if a.name == name)
        return acr.verdict_for(agent, ip, self.ranges, dns or {})

    def test_lists(self):
        self.assertEqual(self.v("Googlebot", "66.249.66.1"), "verified (IP list)")
        self.assertEqual(self.v("Googlebot", "2001:4860:4801:10::1"), "verified (IP list)")
        self.assertEqual(self.v("ClaudeBot", "216.73.216.10"), "verified (IP list)")
        self.assertEqual(self.v("Claude-Agent", "34.31.25.14"), "verified (IP list)")
        self.assertEqual(self.v("Google-Lens", "74.125.208.4"), "verified (IP list)")
        self.assertEqual(self.v("ClaudeBot", "203.0.113.5"), "unverified")

    def test_a_googlebot_name_from_google_cloud_is_a_customer(self):
        self.assertEqual(self.v("Googlebot", "107.178.192.10"), "unverified (Google Cloud customer)")

    def test_fixed_verdicts(self):
        self.assertEqual(self.v("Claude Code", "198.51.100.7"), "user's machine")
        self.assertEqual(self.v("Applebot", "17.58.100.1"), "no list")
        self.assertEqual(self.v("Google-Extended", "198.51.100.99"), "fake")
        self.assertEqual(self.v("Googlebot", "-"), "not checked")

    def test_dns_results(self):
        key = ("108.177.64.103", acr.GOOGLE_PROXY)
        host = "rate-limited-proxy-108-177-64-103.google.com"
        self.assertEqual(self.v("Google (Gemini)", "108.177.64.103", {key: host}), "verified (DNS)")
        self.assertEqual(self.v("Google (Gemini)", "108.177.64.103", {key: None}), "unverified")
        self.assertEqual(self.v("Google (Gemini)", "108.177.64.103", {key: acr.SKIPPED}), "not checked")

    def test_no_lists_means_not_checked(self):
        agent = next(a for a in acr.AGENTS if a.name == "ClaudeBot")
        self.assertEqual(acr.verdict_for(agent, "203.0.113.5", {}, {}), "not checked")


class Dns(unittest.TestCase):
    def test_fcrdns(self):
        rdns = {"108.177.64.103": "rate-limited-proxy-108-177-64-103.google.com.", "203.0.113.9": "evil.example.com",
                "198.51.100.3": "crawl-1.googlebot.com.evil.example"}
        fwd = {"rate-limited-proxy-108-177-64-103.google.com": "108.177.64.103"}

        def gethostbyaddr(ip):
            if ip not in rdns:
                raise OSError("no PTR")
            return rdns[ip], [], [ip]

        def getaddrinfo(host, port):
            if host not in fwd:
                raise OSError("NXDOMAIN")
            return [(2, 1, 6, "", (fwd[host], 0))]

        with mock.patch.object(acr.socket, "gethostbyaddr", gethostbyaddr), \
                mock.patch.object(acr.socket, "getaddrinfo", getaddrinfo):
            self.assertEqual(acr.fcrdns("108.177.64.103", ("google.com",)),
                             "rate-limited-proxy-108-177-64-103.google.com")
            self.assertIsNone(acr.fcrdns("203.0.113.9", ("google.com",)))       # wrong domain
            self.assertIsNone(acr.fcrdns("198.51.100.3", ("googlebot.com",)))   # suffix trick
            self.assertIsNone(acr.fcrdns("192.0.2.1", ("google.com",)))         # no PTR
            fwd["rate-limited-proxy-108-177-64-103.google.com"] = "192.0.2.50"  # PTR points elsewhere
            self.assertIsNone(acr.fcrdns("108.177.64.103", ("google.com",)))

    def test_limit(self):
        with mock.patch.object(acr, "fcrdns", lambda ip, dom: "host.google.com"):
            res = acr.dns_checks({("192.0.2.1", ("google.com",)), ("192.0.2.2", ("google.com",))}, 1, 5)
        self.assertEqual(sorted(res.values(), key=str), ["host.google.com", acr.SKIPPED])


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.out = os.path.join(self.tmp, "report.json")
        gemini = ("108.177.64.103", acr.GOOGLE_PROXY)
        patcher = mock.patch.object(acr, "fcrdns", lambda ip, dom: (
            "rate-limited-proxy-108-177-64-103.google.com" if (ip, dom) == gemini else None))
        patcher.start()
        self.addCleanup(patcher.stop)

    def report(self, *extra, log=LOG):
        code, text = run_cli(log, "--ranges", RANGES, "--json", self.out, *extra)
        self.assertEqual(code, 0)
        return json.loads(read(self.out)), text

    def test_counts(self):
        r, text = self.report("--probe", "twprobe=", "--sitemap", SITEMAP)
        agents = {a["agent"]: a for a in r["agents"]}
        self.assertEqual((r["lines_read"], r["lines_parsed"], r["bot_requests"]), (28, 27, 24))
        g = agents["Googlebot"]
        self.assertEqual((g["requests"], g["trusted"], g["suspect"]), (7, 6, 1))
        self.assertEqual((g["status"]["404"], g["status"]["410"], g["kinds"]["asset"], g["kinds"]["robots.txt"]),
                         (1, 1, 1, 1))
        c = agents["ClaudeBot"]
        self.assertEqual((c["requests"], c["trusted"], c["kinds"]["llms.txt"], c["kinds"]["sitemap"]), (6, 4, 1, 1))
        self.assertEqual(c["status"]["304"], 1)
        self.assertEqual(agents["Google (Gemini)"]["verdicts"], {"verified (DNS)": 1})
        self.assertEqual(agents["Google-Lens"]["verdicts"], {"verified (IP list)": 1})
        self.assertEqual(agents["Google-Agent"]["verdicts"], {"verified (IP list)": 1})
        self.assertEqual(agents["Claude-Agent"]["kinds"], {"page": 1, "asset": 1})
        self.assertEqual(agents["Claude Code"]["verdicts"], {"user's machine": 1})
        self.assertEqual(agents["Google-Extended"]["suspect"], 1)
        suspects = {s["agent"]: s for s in r["suspects"]}
        self.assertEqual(suspects["ClaudeBot"]["requests"], 2)
        self.assertEqual(suspects["Googlebot"]["verdicts"], {"unverified (Google Cloud customer)": 1})
        self.assertFalse(r["behind_cloudflare"])
        probes = {p["request"].split("twprobe=")[1]: p for p in r["probes"]}
        self.assertEqual(len(r["probes"]), 4)
        self.assertEqual(probes["gemini"]["verdict"], "verified (DNS)")
        self.assertEqual(r["probes"][-1]["agent"], None)   # a person who opened the probe URL
        f = r["freshness"]
        self.assertEqual(f["urls_in_window"], 2)
        self.assertEqual(f["agents"]["Googlebot"], {"fetched": 2, "median_hours": 0.6, "within_24h": 2})
        self.assertEqual(f["agents"]["ClaudeBot"]["fetched"], 1)
        self.assertIn("Requests that claim a bot name but failed the IP check", text)

    def test_gzip_and_date_filter(self):
        gz = os.path.join(self.tmp, "access.log.2.gz")
        with open(LOG, "rb") as src, gzip.open(gz, "wb") as dst:
            dst.write(src.read())
        r, _ = self.report("--since", "2026-11-12", "--until", "2026-11-13", log=gz)
        self.assertEqual(r["bot_requests"], 24)
        r, _ = self.report("--since", "2026-11-13", log=gz)
        self.assertEqual(r["bot_requests"], 0)

    def test_no_ips_hides_addresses(self):
        r, text = self.report("--probe", "twprobe=", "--no-ips")
        self.assertNotIn("203.0.113.5", text)
        self.assertNotIn("198.51.100.7", text)
        self.assertTrue(all(p["ip"] == "(hidden)" for p in r["probes"]))

    def test_without_ip_lists_nothing_is_verified(self):
        empty = os.path.join(self.tmp, "none")
        os.mkdir(empty)
        code, text = run_cli(LOG, "--ranges", empty, "--no-dns")
        self.assertEqual(code, 0)
        self.assertIn("none loaded", text)

    def test_cloudflare_addresses_raise_a_warning(self):
        log = os.path.join(self.tmp, "cf.log")
        with open(log, "w") as fh:
            for i in range(3):
                fh.write(f'104.16.0.{i + 1} - - [12/Nov/2026:06:00:0{i} +0000] "GET / HTTP/1.1" 200 5 "-" '
                         '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"\n')
        r, text = self.report(log=log)
        self.assertTrue(r["behind_cloudflare"])
        self.assertIn("WARNING", text)

    def test_stdin(self):
        with open(LOG, "rb") as fh, mock.patch("sys.stdin", io.TextIOWrapper(io.BytesIO(fh.read()))):
            r, _ = self.report(log="-")
        self.assertEqual(r["bot_requests"], 24)


if __name__ == "__main__":
    unittest.main()
