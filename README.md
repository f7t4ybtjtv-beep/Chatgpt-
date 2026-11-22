# contact-identifier 🔎

**An open-source OSINT toolkit — with an AI layer — to help you identify and risk-assess *who is contacting you*.**

Someone emails, calls, or DMs you out of the blue. Is it a real person? A business? A scammer or a bot? `contact-identifier` takes the identifier they used to reach you — an **email**, **phone number**, **username**, or **domain** — gathers signals from public/open sources, scores the risk, and writes you a short, plain-language verdict.

It runs **fully offline by default** (deterministic heuristics, no API keys, no network) and can optionally pull in live public lookups and an LLM write-up when you turn them on.

---

## ⚖️ Read this first — responsible use

This tool is built for **defensive, personal-safety** use: deciding whether to trust an unsolicited contact.

- ✅ **Do**: vet unknown senders/callers, spot phishing, scams, and spoofing, protect yourself and non-technical people you help.
- ❌ **Don't**: stalk, harass, dox, surveil, or de-anonymise people; build profiles on unwilling targets; or use it against anyone in ways that are illegal where you live (GDPR, CFAA, local privacy law, etc.).
- It only ever touches **public, unauthenticated** data and reports **presence/absence + metadata**, never content scraped from behind a login.
- It is a **decision aid, not proof**. It never claims certainty about a real person's identity. "No red flags" is not "safe".

You are responsible for how you use it.

---

## Install

```bash
# Core (zero dependencies, offline heuristics only)
pip install -e .

# Recommended: full offline + opt-in network detectors
pip install -e ".[full]"

# Optional AI write-up (pick one)
pip install -e ".[llm]"      # Anthropic
pip install -e ".[openai]"   # OpenAI
```

Python 3.10+.

## Quick start

```bash
contact-id someone@example.com
contact-id "+1 202-555-0142" --region US
contact-id johndoe --kind username
contact-id suspicious-site.top --json
```

As a library:

```python
from contact_identifier import identify

report = identify("throwaway@mailinator.com")
print(report.risk)      # Risk.HIGH
print(report.summary)   # plain-language assessment
report.to_dict()        # structured JSON-ready dict
```

Try the offline demo:

```bash
python examples/demo.py
```

## What each detector looks at

| Type | Offline signals | Opt-in network signals |
|------|-----------------|------------------------|
| **email** | syntax, disposable/free/corporate provider, role & no-reply addresses, Gmail canonicalisation | MX records (can it receive mail?), Gravatar profile |
| **phone** | validity, country/region, carrier, line type (VOIP / toll-free / premium-rate scam flags) — all via offline `phonenumbers` metadata | — |
| **username** | candidate public profile URLs | presence check across GitHub, Reddit, Instagram, X, Telegram, TikTok, and more (handle-reuse signal) |
| **domain** | punycode/lookalike detection, low-trust TLDs | WHOIS domain age (young domains = classic scam flag), DNS |

Each finding is a **Signal** with a risk level (`info` / `low` / `medium` / `high`). The report's overall risk is the worst signal, bumped up when several medium flags cluster.

## The AI layer

By default the summary is a fast, **deterministic heuristic** — no key, no network. Turn on an LLM for a richer natural-language assessment:

```bash
export CONTACT_ID_USE_LLM=1
export ANTHROPIC_API_KEY=sk-...        # or OPENAI_API_KEY=...
contact-id someone@example.com
```

**Privacy by design:** only the anonymised *signal list* (e.g. "disposable domain: high") is sent to the LLM — never your own name, email, or notes. If the LLM call fails for any reason, it silently falls back to the heuristic.

## Enabling network lookups

Network detectors are **off by default** so the tool is safe, quiet, and deterministic. Enable them explicitly:

```bash
export CONTACT_ID_ALLOW_NETWORK=1
contact-id someone@example.com     # now also checks MX, Gravatar, etc.
contact-id johndoe --kind username # now actually probes public profiles
```

All outbound requests use a neutral, generic User-Agent and never carry your identity.

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `CONTACT_ID_ALLOW_NETWORK` | off | enable live public lookups (MX, Gravatar, profiles, WHOIS) |
| `CONTACT_ID_USE_LLM` | off | use an LLM for the write-up instead of the heuristic |
| `CONTACT_ID_LLM_MODEL` | provider default | override the model id |
| `CONTACT_ID_DATA_DIR` | `./data` | location of `disposable_domains.txt` / `platforms.json` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | — | LLM credentials |

## Scripting

The CLI exits **1** when any identifier scores HIGH risk, **0** otherwise — so you can wire it into filters or automations. `--json` emits structured output for one or many identifiers; `--stdin` reads one identifier per line.

## Project layout

```
src/contact_identifier/
  core.py            # orchestration: route identifier -> detectors -> report
  models.py          # Signal / Report / Risk dataclasses
  utils.py           # identifier type detection + safe HTTP
  detectors/         # email, phone, username, domain
  ai/summarizer.py   # heuristic + LLM write-up (pluggable)
  cli.py             # contact-id command
data/                # editable disposable-domain + platform lists
tests/               # offline, network-free test suite
examples/demo.py
```

## Extending it

- **Add a platform** to check usernames against: append to `data/platforms.json`.
- **Add disposable domains**: append to `data/disposable_domains.txt`.
- **Add a detector**: drop a `run(value, report)` module in `detectors/` and wire it in `core.py`.

## Tests

```bash
pip install -e ".[dev]"
pytest -q          # 18 tests, fully offline
```

## License

MIT — see [LICENSE](LICENSE).
