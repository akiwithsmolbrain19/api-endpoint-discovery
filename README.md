# API Endpoint Discovery

Crawl a website, discover likely API endpoints, and analyze them — against a live target, with JSON output.

## Pipeline

```
Target URL
  → Crawler (crawler.py)
  → API Discovery (endpoint_discovery.py)
  → Endpoint Analysis (endpoint_analysis.py)
  → JSON results
```

## Setup

Create and activate a virtual environment, then install dependencies:

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```powershell
# Windows (PowerShell)
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

All commands below assume the venv is activated, so `python` is enough.

## Usage

```bash
# Crawl only
python crawler.py http://localhost:8000/

# Crawl + discover + analyze (prints JSON)
python crawler.py http://localhost:8000/ --analyze

# Save analysis to a file
python crawler.py http://localhost:8000/ --analyze -o results.json

# Limit crawl size (default: 50 pages)
python crawler.py https://example.com/ --analyze --max-pages 20
```

## How discovery works

`discover_endpoints(crawl_records, target_url)` combines four sources (deduplicated, source-tagged):

| Source | Method |
|---|---|
| `crawler` | Passive filter on crawled pages: `/api/`, `/v1/`, `/v2/`, `/graphql`, `.json`, JSON content types |
| `javascript` | Static scan of same-origin `<script>` files for API string references (`fetch`, `axios`, …). No JS execution |
| `openapi` / `swagger` | Probes common spec locations (`/openapi.json`, `/api-docs`, …) and extracts `paths` keys |
| `common_path` | Small built-in wordlist (14 entries) probed with GET only |

Every candidate is `{"url": ..., "source": ..., "sources": [...]}`.

## Analysis output

Each analyzed endpoint records `url, source, sources, method, status, content_type, parameters, response_structure, api_behavior (confirmed/likely/uncertain/unlikely), access (public/authentication_required/unknown), response_time_ms, warnings, error`. Only safe GET requests are sent; one failing endpoint never stops the batch.

## Testing

```bash
make test          # unit tests (no network)
make server        # serve the local test site on :8000
```

End-to-end against the included test site or OWASP Juice Shop (`http://localhost:3000`):

```bash
python crawler.py http://localhost:3000/ --analyze -o results.json
```

## Known limitations

- The crawler follows `<a href>` links only — JavaScript-rendered/SPAs yield few pages (discovery compensates via JS inspection).
- Discovery is heuristic, not exhaustive: no recursive fuzzing, no huge wordlists.
- The analyzer sends GET requests only — endpoints requiring POST/PUT/DELETE are reported by their GET behavior.
- Dynamically constructed API URLs (e.g. JS template literals like `` `/api/products/${id}/price` ``) are not currently extracted.
