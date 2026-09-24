import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def fetch_page(url):
    response = requests.get(url, timeout=5)

    print("Status:", response.status_code)

    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")

    return response.text, response.status_code, content_type


def extract_links(html, current_url):
    soup = BeautifulSoup(html, "html.parser")

    links = []

    for link in soup.find_all("a"):

        href = link.get("href")

        if href:
            full_url = urljoin(current_url, href)
            links.append(full_url)

    return links


def is_allowed(url, domain):
    return urlparse(url).netloc == domain


def crawl(start_url, max_pages=50):

    domain = urlparse(start_url).netloc

    visited = set()
    seen = set([start_url])
    queue = [start_url]
    results = []

    while queue:

        if len(visited) >= max_pages:
            print(f"\nReached max_pages={max_pages}, stopping.")
            break

        url = queue.pop(0)

        if url in visited:
            continue

        print("\nCrawling:", url)

        try:

            html, status, content_type = fetch_page(url)

            visited.add(url)
            results.append(
                {"url": url, "status": status, "content_type": content_type}
            )

            links = extract_links(html, url)

            for link in links:

                if (
                    is_allowed(link, domain)
                    and link not in visited
                    and link not in seen
                ):
                    seen.add(link)
                    queue.append(link)

        except requests.HTTPError as e:

            if e.response is not None and e.response.status_code == 404:
                print(f"Skipping 404: {url}")
            else:
                print("HTTP Error:", e)

        except requests.RequestException as e:

            print("Error:", e)

    return results


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Basic HTTP crawler")
    parser.add_argument("start_url", nargs="?", help="URL to start crawling from")
    parser.add_argument("--analyze", action="store_true", help="Analyze discovered API endpoints")
    parser.add_argument("--output", "-o", default=None, help="Write analysis JSON to file")
    parser.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl (default: 50)")
    args = parser.parse_args()

    start_url = args.start_url or input("Enter start URL: ").strip()

    if not start_url:
        print("No URL provided. Usage: python crawler.py <start_url> [--analyze]")
        sys.exit(1)

    if not start_url.startswith(("http://", "https://")):
        start_url = "http://" + start_url

    records = crawl(start_url, max_pages=args.max_pages)

    print("\nFinished!")
    print("Pages visited:", len(records))

    candidates = []
    try:
        from endpoint_discovery import discover_endpoints

        candidates = discover_endpoints(records, start_url)
        print(f"API candidates: {len(candidates)}")
        for candidate in candidates:
            src = candidate.get("source", "crawler")
            print(f"  - {candidate['url']} [{src}]")
    except ImportError:
        pass

    if args.analyze:
        try:
            from endpoint_analysis import EndpointAnalyzer
        except ImportError:
            print("endpoint_analysis.py not found, cannot analyze.")
            sys.exit(1)
        with EndpointAnalyzer() as analyzer:
            results = analyzer.analyze_candidates(candidates)
        print(f"\nAnalyzed {len(results)} endpoints:")
        for r in results:
            print(f"  - {r.get('url')} -> {r.get('status')} [{r.get('api_behavior', {}).get('classification')}/{r.get('access', {}).get('classification')}]")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
            print(f"Wrote analysis to {args.output}")
        else:
            print(json.dumps(results, indent=2))
