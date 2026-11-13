# AI crawler log report

Find out which AI crawlers and agents read your site, and which of them are real. The script reads your web
server's access log, names every request from a known AI or search bot, and checks the client address against the
IP lists that Anthropic, Google, OpenAI, Perplexity and Microsoft publish. Google agents missing from those lists
are checked by reverse and forward DNS, the way Google documents.

This is the code from the TrickyWorld article
[AI crawlers vs AEO: Claude and Gemini in our logs](https://www.trickyworld.in/artificial-intelligence-machine-learning/ai-agents/ai-crawlers-claude-gemini-logs/),
which explains what each bot is for and what the numbers mean.

One file, Python 3.10 or newer, standard library only. Nothing to install.

## Quick start

```bash
git clone https://github.com/vishal1610kamal/trickyworld_ai_crawler_log.git
cd trickyworld_ai_crawler_log
python3 ai_crawl_report.py --update-ranges          # downloads 15 IP lists into ./ranges
python3 ai_crawl_report.py access.log access.log.2.gz
```

On Debian and Ubuntu, Apache and Nginx logs are readable only by root and the `adm` group. Let root read them and
run the script as yourself:

```bash
sudo zcat -f /var/log/apache2/access.log* | python3 ai_crawl_report.py -
sudo zcat -f /var/log/nginx/access.log* | python3 ai_crawl_report.py -
```

`zcat -f` reads the current log, the `.1` file and the rotated `.gz` files alike.

## Options

| Option | What it does |
|---|---|
| `--update-ranges` | Download the IP lists again (operators change them; run it before each report) |
| `--sitemap FILE_OR_URL` | Freshness: how soon each agent fetched URLs whose `lastmod` falls inside the log period |
| `--probe TEXT` | Show every request whose URL contains `TEXT`, bot or not (see "Probe test" below) |
| `--since` / `--until YYYY-MM-DD` | Only requests in that window (UTC) |
| `--no-dns` | Skip the DNS check for Google agents that aren't in Google's lists |
| `--no-ips` | Hide IP addresses, so you can share the output |
| `--json FILE` | Also write everything as JSON |
| `--top N` | Pages to list per agent (default 5) |

## What it recognises

| Operator | Agents | How a request is verified |
|---|---|---|
| Anthropic | ClaudeBot (training), Claude-SearchBot (search), Claude-User (fetches for a user), Claude-Agent (hosted browser) | `claude.com/crawling/bots.json`; Claude-Agent from `claude.com/.well-known/sail` |
| Anthropic | Claude Code (`Claude-User (claude-code/...)`) | Can't be: it runs on the developer's own machine and connection |
| Google | Googlebot, GoogleOther, Google-CloudVertexBot, Google-InspectionTool, Storebot-Google | `common-crawlers.json` or DNS ending in `googlebot.com` |
| Google | Google-Agent | `user-triggered-agents.json` |
| Google | Gemini (bare `Google`), AI Mode (`Google-Lens`), Google-GeminiNotebook, other user-triggered fetchers | `user-triggered-fetchers-google.json` or DNS ending in `google.com` |
| Google | AdsBot, Mediapartners-Google | `special-crawlers.json` or DNS ending in `google.com` |
| OpenAI | GPTBot, OAI-SearchBot, ChatGPT-User, OAI-AdsBot | `openai.com/*.json` |
| Perplexity | PerplexityBot, Perplexity-User | `perplexity.ai/*.json` |
| Microsoft | bingbot | `bing.com/toolbox/bingbot.json` |
| Others | Applebot, Meta, Bytespider, CCBot, Amazonbot, DuckAssistBot, MistralAI-User | Named only (no list loaded) |

The bare `Google` and `Google-Lens` user agents are not in Google's documentation. Dave Smart of Tame the Bots
traced them to Gemini and AI Mode on
[3 November 2026](https://tamethebots.com/blog-n-bits/google-and-google-lens-user-agents); treat those two labels
as observations that may change.

A user agent containing `Google-Extended` is always fake: Google-Extended is a robots.txt token only, and Google
never sends it in a request.

## Verdicts

| Verdict | Meaning |
|---|---|
| `verified (IP list)` | The address is in the operator's published list for that agent |
| `verified (DNS)` | Reverse DNS gives the operator's domain, and that name resolves back to the same address |
| `user's machine` | Claude Code: a real request can come from any address |
| `no list` | Named by user agent only; nothing was checked |
| `not checked` | The list wasn't downloaded, the log has no IP, or the DNS lookup was skipped or timed out |
| `unverified` | Lists were checked and the address isn't in them: most likely someone using the bot's name |
| `unverified (Google Cloud customer)` | A Google bot name from Google Cloud addresses that any Google Cloud customer can rent |
| `fake` | A user agent no real request carries |

Only trusted requests (verified, user's machine, no list, not checked) count in the status, special-file and
top-page tables. Everything else is listed under "Requests that claim a bot name but failed the IP check".

## Behind a CDN

If Cloudflare or another proxy sits in front of your server, two things change:

1. **Your log must record the visitor, not the proxy.** On Apache, enable `mod_remoteip` with
   `RemoteIPHeader CF-Connecting-IP` and `RemoteIPTrustedProxy` lines for Cloudflare's ranges; on Nginx, use
   `set_real_ip_from` and `real_ip_header CF-Connecting-IP`. If most bot requests come from Cloudflare addresses,
   the report prints a warning, because then nothing can be verified.
2. **Cached requests never reach your server.** A crawler that gets a page from the CDN's cache leaves no line in
   your log, so every count here is a floor, and a freshness figure is the first fetch that reached your server,
   which can be later than the agent's real first fetch. Cloudflare's AI Crawl Control dashboard counts requests at
   the edge, cache hits included. Use it for volumes, and this report for who is real and what reached your server.

## Probe test

To see exactly how an assistant fetches your pages, ask it to open a URL with a marker nobody else will use, then
look for the marker:

```text
fetch the page "https://www.example.com/some-post/?probe=gemini-1" and tell me what it says
```

```bash
sudo zcat -f /var/log/apache2/access.log* | python3 ai_crawl_report.py - --probe probe=
```

The query string makes the URL new to every cache, so the request reaches your server.

## Privacy and safety

- The script reads logs and writes only its own report. It never runs anything it downloads: the IP lists are parsed
  as JSON, TOML or plain text, and bad entries are skipped.
- Run it as an ordinary user. Only `zcat` needs root to read the logs.
- People's visits are parsed and ignored. The report prints addresses only for requests that claim a bot name
  (and for probe matches); `--no-ips` hides those too.

## Tests

```bash
python3 -m unittest -v
```

The tests use a made-up sample log (`tests/fixtures/sample_access.log`) with documentation-range addresses, real
prefixes copied from each operator's list, and a fake DNS resolver, so they need no network.

## Limits

- The log has to be in the Apache/Nginx `combined` format (Apache's `vhost_combined` works too).
- A request with an operator's user agent from an address that isn't listed is reported, not blocked. Lists lag
  behind new addresses now and then, so check before you block.
- `lastmod` in a sitemap is the last change, not the publish date: editing a post restarts its freshness clock.

## Sources

- Anthropic: [Does Anthropic crawl data from the web?](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler),
  [How do Anthropic-hosted browsers identify themselves?](https://support.claude.com/en/articles/18234133)
- Google: [Verify requests from Google crawlers and fetchers](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests),
  [user-triggered fetchers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers),
  [common crawlers](https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers)
- OpenAI: [Overview of OpenAI crawlers](https://developers.openai.com/api/docs/bots)
- Perplexity: [Perplexity crawlers](https://docs.perplexity.ai/guides/bots)
- Cloudflare: [AI Crawl Control](https://developers.cloudflare.com/ai-crawl-control/)
