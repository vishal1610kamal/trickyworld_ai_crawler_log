#!/usr/bin/env python3
"""Which AI crawlers and agents read your site, checked against the IP lists their operators publish.

Reads web server access logs in the Apache/Nginx "combined" format (plain or gzip files, or "-" for
stdin), names every request from a known AI or search bot, and checks the client address against the
IP lists that Anthropic, Google, OpenAI, Perplexity and Microsoft publish. Python 3.10+, standard
library only.

    python3 ai_crawl_report.py --update-ranges                  # download the IP lists into ./ranges
    sudo zcat -f /var/log/apache2/access.log* | python3 ai_crawl_report.py -
"""
from __future__ import annotations

import argparse
import functools
import gzip
import ipaddress
import json
import os
import re
import socket
import statistics
import sys
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- IP lists
# Where each operator publishes the addresses its bots use. All JSON files share Google's format
# ({"creationTime": ..., "prefixes": [{"ipv4Prefix": ...}, {"ipv6Prefix": ...}]}); Anthropic's hosted
# browser (Claude-Agent) is listed in a SAIL file (TOML), Cloudflare's edge in plain text.
G = "https://developers.google.com/static/crawling/ipranges/"
RANGE_SOURCES = {
    "anthropic-bots": ("https://claude.com/crawling/bots.json", "json"),
    "anthropic-sail": ("https://claude.com/.well-known/sail", "sail"),
    "google-common": (G + "common-crawlers.json", "json"),
    "google-special": (G + "special-crawlers.json", "json"),
    "google-fetchers": (G + "user-triggered-fetchers-google.json", "json"),
    "google-agents": (G + "user-triggered-agents.json", "json"),
    "google-cloud-users": (G + "user-triggered-fetchers.json", "json"),
    "openai-gptbot": ("https://openai.com/gptbot.json", "json"),
    "openai-searchbot": ("https://openai.com/searchbot.json", "json"),
    "openai-chatgpt-user": ("https://openai.com/chatgpt-user.json", "json"),
    "openai-adsbot": ("https://openai.com/adsbot.json", "json"),
    "perplexity-bot": ("https://www.perplexity.ai/perplexitybot.json", "json"),
    "perplexity-user": ("https://www.perplexity.ai/perplexity-user.json", "json"),
    "bing-bingbot": ("https://www.bing.com/toolbox/bingbot.json", "json"),
    "cloudflare": (("https://www.cloudflare.com/ips-v4/", "https://www.cloudflare.com/ips-v6/"), "text"),
}
SAIL_SERVICE = "Claude-Agent"
EXT = {"json": ".json", "sail": ".toml", "text": ".txt"}


# --------------------------------------------------------------------------- agents
@dataclass(frozen=True)
class Agent:
    name: str
    operator: str
    purpose: str
    pattern: re.Pattern
    ranges: tuple = ()         # IP lists that prove this agent
    dns: tuple = ()            # accepted reverse-DNS domains (forward-confirmed)
    verdict: str = ""          # fixed verdict when an IP check can't apply
    note: str = ""


def _a(name, operator, purpose, regex, ranges=(), dns=(), verdict="", note="", flags=re.I):
    return Agent(name, operator, purpose, re.compile(regex, flags), tuple(ranges), tuple(dns), verdict, note)


GOOGLE_CRAWL = ("googlebot.com",)   # crawl-*.googlebot.com, geo-crawl-*.geo.googlebot.com
GOOGLE_PROXY = ("google.com",)      # google-proxy-*.google.com, rate-limited-proxy-*.google.com

# Order matters: the first pattern that matches the user agent wins.
AGENTS = [
    # Anthropic: support.claude.com/en/articles/8896518 and /18234133
    _a("Claude-Agent", "Anthropic", "agent", r"\bClaude-Agent\b", ["anthropic-sail"],
       note="Anthropic-hosted browser acting for a user"),
    _a("Claude-SearchBot", "Anthropic", "search", r"\bClaude-SearchBot\b", ["anthropic-bots"]),
    _a("Claude Code", "Anthropic", "user fetch", r"\bclaude-code/", verdict="user's machine",
       note="Claude Code's WebFetch sends Claude-User from the developer's own connection"),
    _a("Claude-User", "Anthropic", "user fetch", r"\bClaude-User\b", ["anthropic-bots"]),
    _a("ClaudeBot", "Anthropic", "training", r"\bClaudeBot\b", ["anthropic-bots"]),
    # Google: developers.google.com/crawling/docs/crawlers-fetchers/
    _a("Google-Agent", "Google", "agent", r"\bGoogle-Agent\b", ["google-agents"],
       note="agents hosted on Google infrastructure"),
    _a("Google-GeminiNotebook", "Google", "user fetch", r"\bGoogle-(?:GeminiNotebook|NotebookLM)\b",
       ["google-fetchers"], GOOGLE_PROXY),
    _a("Google-Lens", "Google", "user fetch", r"\bGoogle-Lens\b", ["google-fetchers"], GOOGLE_PROXY,
       note="AI Mode fetches were seen with this user agent (Tame the Bots, 3 Nov 2026)"),
    _a("Google (Gemini)", "Google", "user fetch", r"^Google$", ["google-fetchers"], GOOGLE_PROXY,
       note="Gemini fetches were seen with the bare user agent 'Google' (Tame the Bots, 3 Nov 2026)"),
    _a("Google-Extended", "Google", "fake", r"\bGoogle-Extended\b", verdict="fake",
       note="Google-Extended is a robots.txt token only; no real request carries it"),
    _a("Google-CloudVertexBot", "Google", "site owner's crawl", r"\bGoogle-CloudVertexBot\b",
       ["google-common"], GOOGLE_CRAWL),
    _a("Google-InspectionTool", "Google", "testing tool", r"\bGoogle-InspectionTool\b",
       ["google-common"], GOOGLE_CRAWL),
    _a("GoogleOther", "Google", "other", r"\bGoogleOther\b", ["google-common"], GOOGLE_CRAWL),
    _a("Storebot-Google", "Google", "shopping", r"\bStorebot-Google\b", ["google-common"], GOOGLE_CRAWL),
    _a("Googlebot", "Google", "search", r"\bGooglebot\b", ["google-common"], GOOGLE_CRAWL,
       note="also feeds AI Overviews, AI Mode and Gemini's grounding"),
    _a("Google ads bots", "Google", "ads", r"\b(?:AdsBot-Google|Mediapartners-Google)\b",
       ["google-special"], GOOGLE_PROXY),
    _a("Google fetchers (other)", "Google", "user fetch",
       r"\b(?:Google-Read-Aloud|Google-Pinpoint|GoogleMessages|Google-Site-Verification|"
       r"FeedFetcher-Google|GoogleProducer|Google-CWS)\b", ["google-fetchers"], GOOGLE_PROXY),
    # OpenAI: developers.openai.com/api/docs/bots
    _a("OAI-SearchBot", "OpenAI", "search", r"\bOAI-SearchBot\b", ["openai-searchbot"]),
    _a("ChatGPT-User", "OpenAI", "user fetch", r"\bChatGPT-User\b", ["openai-chatgpt-user"]),
    _a("GPTBot", "OpenAI", "training", r"\bGPTBot\b", ["openai-gptbot"]),
    _a("OAI-AdsBot", "OpenAI", "ads", r"\bOAI-AdsBot\b", ["openai-adsbot"]),
    # Perplexity: docs.perplexity.ai/guides/bots
    _a("Perplexity-User", "Perplexity", "user fetch", r"\bPerplexity-User\b", ["perplexity-user"]),
    _a("PerplexityBot", "Perplexity", "search", r"\bPerplexityBot\b", ["perplexity-bot"]),
    # Microsoft: bing.com/toolbox/bingbot.json
    _a("bingbot", "Microsoft", "search", r"\bbingbot\b", ["bing-bingbot"], note="also Copilot"),
    # Named only (no IP list here); purposes follow Cloudflare's bot reference.
    _a("Applebot", "Apple", "search", r"\bApplebot\b"),
    _a("Meta-ExternalAgent", "Meta", "AI crawler", r"\bmeta-externalagent\b"),
    _a("Meta-ExternalFetcher", "Meta", "user fetch", r"\bmeta-externalfetcher\b"),
    _a("Bytespider", "ByteDance", "AI crawler", r"\bBytespider\b"),
    _a("CCBot", "Common Crawl", "AI crawler", r"\bCCBot\b"),
    _a("Amazonbot", "Amazon", "AI crawler", r"\bAmazonbot\b"),
    _a("DuckAssistBot", "DuckDuckGo", "user fetch", r"\bDuckAssistBot\b"),
    _a("MistralAI-User", "Mistral", "user fetch", r"\bMistralAI-User\b"),
]


ANY_AGENT = re.compile("|".join(f"(?:{a.pattern.pattern})" for a in AGENTS), re.I)


@functools.lru_cache(maxsize=65536)                          # logs repeat the same few thousand UAs
def classify(ua: str) -> Agent | None:
    ua = ua.strip()
    if not ANY_AGENT.search(ua):                              # one search for the many human visitors
        return None
    for agent in AGENTS:
        if agent.pattern.search(ua):
            return agent
    return None


# --------------------------------------------------------------------------- log parsing
LINE = re.compile(
    r'^(?:(?P<vhost>[^\s:]+:\d+) )?'                       # vhost_combined adds "host:port "
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<size>\S+)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
TIME = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
STATIC = re.compile(r"\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|mp4|webm|pdf)$", re.I)


@dataclass
class Hit:
    time: datetime
    ip: str
    method: str
    path: str
    query: str
    status: int
    ua: str
    agent: Agent | None


def parse_time(text: str) -> datetime | None:
    m = TIME.match(text)
    if not m or m.group(2).title() not in MONTHS:
        return None
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    offset = timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
    local = datetime(int(y), MONTHS[mon.title()], int(d), int(hh), int(mm), int(ss), tzinfo=timezone(offset))
    return local.astimezone(timezone.utc)


def unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


def parse_line(line: str) -> Hit | None:
    m = LINE.match(line)
    if not m:
        return None
    when = parse_time(m.group("time"))
    if when is None:
        return None
    parts = unescape(m.group("request")).split(" ")
    method, target = (parts[0], parts[1]) if len(parts) >= 2 else ("-", "-")
    if target.startswith(("http://", "https://")):        # absolute-form request line
        u = urlsplit(target)
        target = (u.path or "/") + (("?" + u.query) if u.query else "")
    path, _, query = target.partition("?")
    status = int(m.group("status")) if m.group("status") != "-" else 0
    ua = unescape(m.group("ua") or "")
    return Hit(when, m.group("ip"), method, path, query, status, ua, classify(ua))


def read_lines(paths):
    for p in paths:
        if p == "-":
            yield from sys.stdin.buffer
            continue
        opener = gzip.open if p.endswith(".gz") else open
        with opener(p, "rb") as fh:
            yield from fh


def path_kind(path: str) -> str:
    p = path.lower()
    if p == "/robots.txt":
        return "robots.txt"
    if p in ("/llms.txt", "/llms-full.txt"):
        return "llms.txt"
    if re.search(r"(?:^|/)[^/]*sitemap[^/]*\.xml(?:\.gz)?$", p):
        return "sitemap"
    if re.search(r"(?:^|/)(?:feed|rss|atom)(?:\.xml)?/?$|\.(?:rss|atom)$", p):
        return "feed"
    if p.startswith("/_next/") or STATIC.search(p):
        return "asset"
    return "page"


def status_bucket(code: int) -> str:
    if code == 304:
        return "304"
    if code in (404, 410):
        return str(code)
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if code >= 500:
        return "5xx"
    return "other"


# --------------------------------------------------------------------------- IP lists: load and update
def parse_json_ranges(text: str):
    data = json.loads(text)
    nets = []
    for p in data.get("prefixes", []):
        prefix = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        try:
            nets.append(ipaddress.ip_network(prefix, strict=False))
        except (TypeError, ValueError):
            continue
    return nets, str(data.get("creationTime", ""))


def parse_sail(text: str, service: str = SAIL_SERVICE):
    """Prefixes a SAIL file (draft-kelley-webbotauth-sail-00) lists for one service."""
    try:
        import tomllib                                       # Python 3.11+
        data = tomllib.loads(text)
    except ImportError:
        data = _mini_toml(text)
    sets = {s.get("name"): s for s in data.get("prefix_sets", [])}
    nets = []
    for svc in data.get("services", []):
        if svc.get("name") != service:
            continue
        for set_name in svc.get("prefix_sets", []):
            ps = sets.get(set_name, {})
            for prefix in list(ps.get("ipv4_prefixes", [])) + list(ps.get("ipv6_prefixes", [])):
                try:
                    nets.append(ipaddress.ip_network(prefix, strict=False))
                except ValueError:
                    continue
    return nets, str(data.get("modified", ""))


def _mini_toml(text: str) -> dict:
    """The subset of TOML that SAIL files use, for Python 3.10: [[tables]], strings, arrays, scalars."""
    root: dict = {}
    current = root
    pending_key, buf = None, ""
    for raw in text.splitlines():
        line = _strip_comment(raw).strip()
        if pending_key:                                       # inside a multi-line array
            buf += " " + line
            if buf.count("[") <= buf.count("]"):
                current[pending_key] = _toml_value(buf)
                pending_key, buf = None, ""
            continue
        if not line:
            continue
        m = re.fullmatch(r"\[\[\s*([A-Za-z0-9_.-]+)\s*\]\]", line)
        if m:
            current = {}
            root.setdefault(m.group(1), []).append(current)
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if value.startswith("[") and value.count("[") > value.count("]"):
            pending_key, buf = key, value
            continue
        current[key] = _toml_value(value)
    return root


def _strip_comment(line: str) -> str:
    out, quoted = [], False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        if ch == "#" and not quoted:
            break
        out.append(ch)
    return "".join(out)


def _toml_value(value: str):
    value = value.strip()
    if value.startswith("["):
        return re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value in ("true", "false"):
        return value == "true"
    try:
        return int(value)
    except ValueError:
        return value                                          # datetimes etc. stay as text


def parse_text_ranges(text: str):
    nets = []
    for line in text.split():
        try:
            nets.append(ipaddress.ip_network(line.strip(), strict=False))
        except ValueError:
            continue
    return nets, ""


PARSERS = {"json": parse_json_ranges, "sail": parse_sail, "text": parse_text_ranges}


def load_ranges(folder: str) -> dict:
    ranges = {}
    for key, (_, kind) in RANGE_SOURCES.items():
        path = os.path.join(folder, key + EXT[kind])
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                nets, created = PARSERS[kind](fh.read())
        except (OSError, ValueError) as err:
            print(f"warning: can't read {path}: {err}", file=sys.stderr)
            continue
        if nets:
            if not created:
                created = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).strftime("%Y-%m-%d (file date)")
            ranges[key] = {"nets": nets, "created": created}
    return ranges


def fetch(url: str, timeout: float = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"ai-crawl-report/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(5_000_000).decode("utf-8")


def update_ranges(folder: str) -> int:
    os.makedirs(folder, exist_ok=True)
    failures = 0
    for key, (urls, kind) in RANGE_SOURCES.items():
        try:
            text = "\n".join(fetch(u) for u in ((urls,) if isinstance(urls, str) else urls))
            nets, created = PARSERS[kind](text)
            if not nets:
                raise ValueError("no usable prefixes in the file")
        except Exception as err:                              # keep the old copy, report, go on
            failures += 1
            print(f"  {key:20} FAILED: {err}", file=sys.stderr)
            continue
        path = os.path.join(folder, key + EXT[kind])
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(path + ".tmp", path)
        print(f"  {key:20} {len(nets):5} prefixes  {created}")
    return failures


# --------------------------------------------------------------------------- verification
def in_ranges(ip, keys, ranges) -> bool:
    return any(ip in net for k in keys if k in ranges for net in ranges[k]["nets"])


def fcrdns(ip: str, domains: tuple) -> str | None:
    """Reverse DNS, domain check, forward DNS back to the same address. Returns the host name or None."""
    try:
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except (OSError, UnicodeError):
        return None
    if not any(host == d or host.endswith("." + d) for d in domains):
        return None
    try:
        addrs = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError, ValueError):
        return None
    return host if ipaddress.ip_address(ip) in addrs else None


SKIPPED = "skipped"


def dns_checks(pairs, limit: int, timeout: float) -> dict:
    """fcrdns for (ip, domains) pairs, in parallel. Value: host name, None (failed) or SKIPPED (over the
    limit, or no answer in time: neither proves anything)."""
    pairs = sorted(pairs)
    results = {key: SKIPPED for key in pairs[limit:]}
    pool = ThreadPoolExecutor(max_workers=16)
    futures = {pool.submit(fcrdns, ip, dom): (ip, dom) for ip, dom in pairs[:limit]}
    done, _ = wait(futures, timeout=timeout)
    for fut, key in futures.items():
        results[key] = fut.result() if fut in done else SKIPPED
    pool.shutdown(wait=False, cancel_futures=True)
    return results


def verdict_for(agent: Agent, ip_text: str, ranges: dict, dns_results: dict) -> str:
    if agent.verdict:
        return agent.verdict
    if not agent.ranges and not agent.dns:
        return "no list"
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "not checked"                                 # host names in the log, or "-"
    if in_ranges(ip, agent.ranges, ranges):
        return "verified (IP list)"
    dns = dns_results.get((ip_text, agent.dns))
    if dns == SKIPPED:
        return "not checked"
    if dns:
        return "verified (DNS)"
    have_list = any(k in ranges for k in agent.ranges)
    if not have_list and (ip_text, agent.dns) not in dns_results:
        return "not checked"
    if in_ranges(ip, ("google-cloud-users",), ranges):
        return "unverified (Google Cloud customer)"
    return "unverified"


TRUSTED = ("verified (IP list)", "verified (DNS)", "user's machine", "no list", "not checked")


# --------------------------------------------------------------------------- sitemaps (freshness)
def load_sitemap(source: str) -> dict:
    if source.startswith(("http://", "https://")):
        text = fetch(source)
    else:
        with open(source, encoding="utf-8") as fh:
            text = fh.read()
    out = {}
    for block in re.findall(r"<url>(.*?)</url>", text, re.S):
        loc = re.search(r"<loc>\s*([^<\s]+)\s*</loc>", block)
        mod = re.search(r"<lastmod>\s*([^<\s]+)\s*</lastmod>", block)
        if loc and mod:
            when = parse_iso(mod.group(1))
            if when:
                out[urlsplit(loc.group(1)).path or "/"] = when
    return out


def parse_iso(text: str) -> datetime | None:
    text = text.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    return when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when.astimezone(timezone.utc)


# --------------------------------------------------------------------------- report
def build_report(paths, ranges, *, probes=(), since=None, until=None, use_dns=False, dns_limit=300,
                 dns_timeout=20.0, sitemaps=None, top=5) -> dict:
    hits, probe_hits = [], []
    lines = parsed = 0
    first = last = None
    for raw in read_lines(paths):
        lines += 1
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        hit = parse_line(line)
        if hit is None:
            continue
        if (since and hit.time < since) or (until and hit.time >= until):
            continue
        parsed += 1
        first = hit.time if first is None or hit.time < first else first
        last = hit.time if last is None or hit.time > last else last
        if hit.agent:
            hits.append(hit)
        if probes and any(p in hit.path + "?" + hit.query for p in probes):
            probe_hits.append(hit)

    dns_results = {}
    if use_dns:
        need = {(h.ip, h.agent.dns) for h in hits + [p for p in probe_hits if p.agent]
                if h.agent.dns and not h.agent.verdict and _ip_ok(h.ip)
                and not in_ranges(ipaddress.ip_address(h.ip), h.agent.ranges, ranges)}
        dns_results = dns_checks(need, dns_limit, dns_timeout)

    cache = {}

    def verdict(h):
        key = (h.agent.name, h.ip)
        if key not in cache:
            cache[key] = verdict_for(h.agent, h.ip, ranges, dns_results)
        return cache[key]

    per = defaultdict(lambda: {"requests": 0, "verdicts": Counter(), "status": Counter(), "kinds": Counter(),
                               "pages": set(), "ips": set(), "first": None, "last": None, "paths": Counter()})
    suspects = defaultdict(lambda: {"requests": 0, "ips": Counter(), "verdicts": Counter()})
    first_fetch = defaultdict(lambda: defaultdict(list))
    cloudflare_hits = 0
    for h in hits:
        a = h.agent
        v = verdict(h)
        s = per[a.name]
        s["requests"] += 1
        s["verdicts"][v] += 1
        if _ip_ok(h.ip) and in_ranges(ipaddress.ip_address(h.ip), ("cloudflare",), ranges):
            cloudflare_hits += 1
        if v not in TRUSTED:
            sus = suspects[a.name]
            sus["requests"] += 1
            sus["ips"][h.ip] += 1
            sus["verdicts"][v] += 1
            continue
        kind = path_kind(h.path)
        s["status"][status_bucket(h.status)] += 1
        s["kinds"][kind] += 1
        s["ips"].add(h.ip)
        s["first"] = h.time if s["first"] is None or h.time < s["first"] else s["first"]
        s["last"] = h.time if s["last"] is None or h.time > s["last"] else s["last"]
        if kind == "page":
            s["pages"].add(h.path)
            s["paths"][h.path] += 1
            first_fetch[a.name][h.path].append(h.time)

    agents_out = []
    for agent in AGENTS:
        if agent.name not in per:
            continue
        s = per[agent.name]
        trusted = sum(n for v, n in s["verdicts"].items() if v in TRUSTED)
        agents_out.append({
            "agent": agent.name, "operator": agent.operator, "purpose": agent.purpose, "note": agent.note,
            "requests": s["requests"], "trusted": trusted, "suspect": s["requests"] - trusted,
            "verdicts": dict(s["verdicts"]), "status": dict(s["status"]), "kinds": dict(s["kinds"]),
            "distinct_pages": len(s["pages"]), "distinct_ips": len(s["ips"]),
            "first": _iso(s["first"]), "last": _iso(s["last"]),
            "top_pages": s["paths"].most_common(top),
        })

    report = {
        "tool": f"ai_crawl_report {VERSION}",
        "generated": _iso(datetime.now(timezone.utc)),
        "lines_read": lines, "lines_parsed": parsed, "bot_requests": len(hits),
        "period": {"first": _iso(first), "last": _iso(last)},
        "ranges": {k: {"created": v["created"], "prefixes": len(v["nets"])} for k, v in ranges.items()},
        "dns_checked": len(dns_results) if use_dns else None,
        "agents": agents_out,
        "suspects": [{"agent": n, "requests": s["requests"], "verdicts": dict(s["verdicts"]),
                      "distinct_ips": len(s["ips"]), "top_ips": s["ips"].most_common(5)}
                     for n, s in sorted(suspects.items(), key=lambda kv: -kv[1]["requests"])],
        "behind_cloudflare": bool(hits) and "cloudflare" in ranges and cloudflare_hits / len(hits) > 0.5,
        "probes": [{"time": _iso(p.time), "ip": p.ip, "status": p.status, "request": f"{p.method} {p.path}"
                    + (f"?{p.query}" if p.query else ""), "user_agent": p.ua,
                    "agent": p.agent.name if p.agent else None,
                    "verdict": verdict(p) if p.agent else "not a known bot"} for p in probe_hits],
    }
    if sitemaps:
        report["freshness"] = freshness(sitemaps, first_fetch, first, last)
    return report


def freshness(lastmods: dict, first_fetch: dict, start, end) -> dict:
    """For sitemap URLs changed inside the log window: how soon each agent fetched them afterwards."""
    window = {p: t for p, t in lastmods.items() if start and end and start <= t <= end}
    out = {"urls_in_window": len(window), "agents": {}}
    for name, paths in first_fetch.items():
        delays = []
        for path, changed in window.items():
            after = [t for t in paths.get(path, []) if t >= changed]
            if after:
                delays.append((min(after) - changed).total_seconds() / 3600)
        if delays:
            out["agents"][name] = {"fetched": len(delays), "median_hours": round(statistics.median(delays), 1),
                                   "within_24h": sum(d <= 24 for d in delays)}
    return out


def _ip_ok(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _iso(when):
    return when.strftime("%Y-%m-%d %H:%M UTC") if when else None


def redact(report: dict) -> dict:
    for s in report["suspects"]:
        s["top_ips"] = [["(hidden)", n] for _, n in s["top_ips"]]
    for p in report["probes"]:
        p["ip"] = "(hidden)"
    return report


def print_report(r: dict, out=None) -> None:
    w = (out or sys.stdout).write
    w(f"AI crawler report ({r['tool']})\n")
    w(f"Lines read {r['lines_read']:,}, parsed {r['lines_parsed']:,}, from known bots {r['bot_requests']:,}\n")
    w(f"Period {r['period']['first']} to {r['period']['last']}\n")
    if r["ranges"]:
        w("IP lists: " + ", ".join(f"{k} ({v['created'][:10]})" for k, v in r["ranges"].items()) + "\n")
    else:
        w("IP lists: none loaded, so nothing was verified. Run with --update-ranges first.\n")
    if r["behind_cloudflare"]:
        w("WARNING: most bot requests come from Cloudflare's addresses. Your log records the proxy, not the\n"
          "visitor: configure mod_remoteip (Apache) or real_ip (Nginx) with CF-Connecting-IP, or nothing verifies.\n")
    w("\n%-24s %-11s %-18s %8s %8s %8s %6s %6s\n" % ("agent", "operator", "purpose", "requests", "verified",
                                                  "suspect", "pages", "assets"))
    for a in r["agents"]:
        ver = sum(n for v, n in a["verdicts"].items() if v.startswith("verified"))
        w("%-24s %-11s %-18s %8d %8d %8d %6d %6d\n" % (a["agent"][:24], a["operator"][:11], a["purpose"][:18],
                                                       a["requests"], ver, a["suspect"], a["distinct_pages"],
                                                       a["kinds"].get("asset", 0)))
    w("\nStatus codes and special files (trusted requests only)\n")
    w("%-24s %6s %5s %5s %5s %5s %5s %5s | %7s %6s %7s %5s\n" % ("agent", "2xx", "304", "3xx", "404", "410", "4xx",
                                                               "5xx", "robots", "llms", "sitemap", "feed"))
    for a in r["agents"]:
        st, k = a["status"], a["kinds"]
        w("%-24s %6d %5d %5d %5d %5d %5d %5d | %7d %6d %7d %5d\n" % (
            a["agent"][:24], st.get("2xx", 0), st.get("304", 0), st.get("3xx", 0), st.get("404", 0),
            st.get("410", 0), st.get("4xx", 0), st.get("5xx", 0), k.get("robots.txt", 0), k.get("llms.txt", 0),
            k.get("sitemap", 0), k.get("feed", 0)))
    w("\nVerification detail\n")
    for a in r["agents"]:
        w(f"  {a['agent']}: " + ", ".join(f"{v} {n}" for v, n in sorted(a["verdicts"].items())) +
          (f"  [{a['note']}]" if a["note"] else "") + "\n")
    if r["suspects"]:
        w("\nRequests that claim a bot name but failed the IP check\n")
        for s in r["suspects"]:
            ips = ", ".join(f"{ip} ({n})" for ip, n in s["top_ips"])
            w(f"  {s['agent']}: {s['requests']} from {s['distinct_ips']} addresses; top: {ips}\n")
    w("\nMost-fetched pages (trusted requests only)\n")
    for a in r["agents"]:
        if a["top_pages"]:
            w(f"  {a['agent']}: " + "; ".join(f"{p} ({n})" for p, n in a["top_pages"]) + "\n")
    if "freshness" in r:
        f = r["freshness"]
        w(f"\nFreshness: {f['urls_in_window']} sitemap URLs changed inside the log window\n")
        for name, d in sorted(f["agents"].items(), key=lambda kv: kv[1]["median_hours"]):
            w(f"  {name}: fetched {d['fetched']}, median {d['median_hours']} h after lastmod, "
              f"{d['within_24h']} within 24 h\n")
    if r["probes"]:
        w("\nProbe requests\n")
        for p in r["probes"]:
            who = f"{p['agent']}: {p['verdict']}" if p["agent"] else "not a known bot"
            w(f"  {p['time']}  {p['ip']}  {p['status']}  {p['request']}\n    UA: {p['user_agent']}\n    -> {who}\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("logs", nargs="*", help="access log files (.gz is fine) or - for stdin")
    ap.add_argument("--ranges", default=os.path.join(HERE, "ranges"), help="folder with the IP lists")
    ap.add_argument("--update-ranges", action="store_true", help="download the IP lists, then exit")
    ap.add_argument("--no-dns", action="store_true",
                    help="skip the reverse+forward DNS check for Google agents missing from the IP lists")
    ap.add_argument("--dns-limit", type=int, default=300, help="max addresses to look up (default 300)")
    ap.add_argument("--probe", action="append", default=[], help="show requests whose URL contains this text")
    ap.add_argument("--sitemap", action="append", default=[], help="sitemap file or URL, for freshness")
    ap.add_argument("--since", help="only requests on or after this date (YYYY-MM-DD, UTC)")
    ap.add_argument("--until", help="only requests before this date (YYYY-MM-DD, UTC)")
    ap.add_argument("--top", type=int, default=5, help="pages to list per agent (default 5)")
    ap.add_argument("--json", metavar="FILE", help="also write the report as JSON")
    ap.add_argument("--no-ips", action="store_true", help="hide IP addresses (for sharing the output)")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    if args.update_ranges:
        print(f"Downloading IP lists into {args.ranges}")
        return 1 if update_ranges(args.ranges) else 0
    if not args.logs:
        ap.error("give at least one log file, or - to read from stdin")
    day = lambda s: datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc) if s else None
    lastmods = {}
    for source in args.sitemap:
        lastmods.update(load_sitemap(source))
    report = build_report(args.logs, load_ranges(args.ranges), probes=args.probe, since=day(args.since),
                          until=day(args.until), use_dns=not args.no_dns, dns_limit=args.dns_limit,
                          sitemaps=lastmods or None, top=args.top)
    if args.no_ips:
        report = redact(report)
    print_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
