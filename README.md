# Domain Info API

**Live instance:** https://dns.lifestep.io — try `/domain?name=github.com`, spec at `/openapi.json`. Free, no signup.

**Self-host it:** `docker compose up -d`. MIT licensed, no third-party paid services.


A compact FastAPI service that returns useful DNS and verified TLS certificate
information without paid third-party services.

## Run locally

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or use Docker Compose:

```bash
docker compose up --build
```

Compose maps the API to `http://127.0.0.1:8089`. OpenAPI JSON is at
`/openapi.json`, and interactive docs are at `/docs`.

## Endpoints

- `GET /domain?name=example.com`
- `GET /health`
- `GET /` for a tiny usage page

Example:

```bash
curl --get http://127.0.0.1:8089/domain \
  --data-urlencode 'name=BÜCHER.de'
```

The response includes the normalized IDNA/punycode domain, A and AAAA addresses,
MX hosts and priorities, NS and TXT records, SPF and DMARC detection, CNAME, a
minimum observed DNS TTL hint, and a verified TLS certificate summary. A/AAAA,
MX, NS, and TXT results are limited to five records; TXT values are limited to
200 characters.

Each DNS record type has a four-second lookup lifetime. The TLS check performs a
normal certificate-verifying handshake to port 443 with a five-second total budget;
certificate verification is never disabled. TLS connections are attempted only
through globally routable A/AAAA results, preventing the probe from connecting to
private or loopback targets. Failures degrade affected values to `null` and add a
human-readable `note`. Responses are cached in-process for 300 seconds, with a
1,024-domain bound. Each process or worker has its own cache.

Input is normalized to lowercase IDNA ASCII. IP addresses, single-label names,
`localhost`, common private-use suffixes, malformed labels, and names longer than
253 characters are rejected with HTTP 422.

## Honest limits

- This is DNS and TLS intelligence only. It does **not** provide WHOIS or registrar
  ownership, creation, expiration, contact, reputation, or historical data.
- It is **not a security scanner** and does not prove that a domain, host, mail
  system, or website is safe.
- `resolves` reflects A/AAAA results during this request. DNS answers can vary by
  resolver, geography, time, split-horizon configuration, and DNSSEC behavior.
- `ttl_hint` is the smallest TTL observed among returned queries, not a guarantee
  of cache behavior across recursive resolvers.
- SPF and DMARC checks detect records that begin with `v=spf1` and `v=DMARC1`;
  they do not fully validate policy syntax or evaluate includes.
- TLS data is available only when a verified port-443 handshake succeeds. A missing
  TLS result does not imply that the domain itself is invalid.

## Tests

The test suite mocks all DNS and TLS network work:

```bash
PYTHONPATH=. uv run --with-requirements requirements-dev.txt pytest -q
```

<!-- xlink:start -->
## Related free tools

- [XLSX Inspector](https://xlsx.lifestep.io) — check workbooks for macros, external links and hidden sheets
- [DNS and SPF Check](https://dnscheck.lifestep.io) — records, SPF, DMARC and TLS expiry
- [Email Validator](https://emailcheck.lifestep.io) — syntax, MX, disposable and role addresses
- [QR Code Generator](https://qrcode.lifestep.io) — free PNG and SVG API, no signup
- [agent-watch](https://github.com/soul-sol/agent-watch)
- [ai-code-review-prompts](https://github.com/soul-sol/ai-code-review-prompts)
- [claude-md-patterns](https://github.com/soul-sol/claude-md-patterns)
- [claude-code-orchestration-ko](https://github.com/soul-sol/claude-code-orchestration-ko)
- [xlsx-inspector-api](https://github.com/soul-sol/xlsx-inspector-api)
- [email-validator-api](https://github.com/soul-sol/email-validator-api)
- [qr-code-api](https://github.com/soul-sol/qr-code-api)

The paid guide collection is available at [lifestep1.gumroad.com](https://lifestep1.gumroad.com).
<!-- xlink:end -->
