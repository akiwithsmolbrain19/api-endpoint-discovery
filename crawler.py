import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def fetch_page(url):
    response = requests.get(url, timeout=5)

    print("Status:", response.status_code)

    return response.text


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


def crawl(start_url):

    domain = urlparse(start_url).netloc

    visited = set()
    queue = [start_url]

    while queue:

        url = queue.pop(0)

        if url in visited:
            continue

        print("\nCrawling:", url)

        visited.add(url)

        try:

            html = fetch_page(url)

            links = extract_links(html, url)

            for link in links:

                if (
                    is_allowed(link, domain)
                    and link not in visited
                ):
                    queue.append(link)

        except requests.RequestException as e:

            print("Error:", e)

    return visited


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        start_url = sys.argv[1]
    else:
        start_url = input("Enter start URL: ").strip()

    if not start_url:
        print("No URL provided. Usage: python crawler.py <start_url>")
        sys.exit(1)

    if not start_url.startswith(("http://", "https://")):
        start_url = "http://" + start_url

    visited = crawl(start_url)

    print("\nFinished!")
    print("Pages visited:", len(visited))
