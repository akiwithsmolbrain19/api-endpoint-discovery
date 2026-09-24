"""Endpoint Analysis & Validation module.

Abhishek's module in the academic cybersecurity pipeline:

    crawler.py -> endpoint_discovery.py -> discovery JSON -> endpoint_analysis.py

This module consumes the JSON produced by the endpoint-discovery module and,
for every candidate endpoint, performs a single safe GET request and produces
one detailed structured record: method, status, content type, parameters,
response structure, API-behavior classification, access classification,
redirect information, timing, size, selected headers, warnings and errors.

It does NOT crawl, discover endpoints, exploit vulnerabilities, brute force
credentials, or build any CLI/dashboard/database.  Only GET requests are sent
automatically; no bodies or payloads are ever transmitted.
"""

from __future__ import annotations

import html
import json
import logging
import re
import sys
import time
from typing import Any
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    RequestException,
    SSLError,
    Timeout,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SCHEMA_DEPTH = 4          # depth limit for JSON structure inference
MAX_KEYS_PER_OBJECT = 50      # keys kept per inferred object
MAX_ARRAY_ITEMS_TO_INSPECT = 5
CHUNK_SIZE = 8192             # incremental body-read chunk size

BODY_READ_LIMIT = 65536       # bytes of decoded body inspected for structure
MAX_PARAM_EXAMPLE = 40        # max length of an example query value
MAX_HEADER_VALUE = 200        # max retained header value length
MAX_FOUND_IN = 5              # provenance entries kept per result
FOUND_IN_TRUNCATE = 300       # per-entry truncation length

REDACTED = "REDACTED"

SOURCE_DEFAULT = "endpoint_discovery"

# Sensitive parameter/value patterns (matched after normalization).
SENSITIVE_PATTERNS = (
    "token", "key", "secret", "password", "passwd", "pwd", "auth",
    "session", "cookie", "jwt", "code", "signature", "credential",
)

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

PAGINATION_FIELDS = (
    "page", "limit", "offset", "per_page", "total", "count",
    "next", "previous", "has_more",
)
DATA_WRAPPERS = ("data", "results", "items", "records")

# Login/authentication path pattern used by api_behavior rule 12 / access rule 3.
LOGIN_PATH_RE = re.compile(r"(log-?in|sign-?in|sso|oauth2?|authorize)([/.]|$)", re.I)

# Obvious path identifiers: pure digits or a UUID.
NUMERIC_SEG_RE = re.compile(r"\d+")
UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_BINARY_TYPES = {
    "application/pdf", "application/zip", "application/octet-stream",
    "application/x-javascript", "application/javascript", "text/javascript",
    "image/svg+xml",
}
_JS_CSS_TYPES = {
    "application/javascript", "application/x-javascript", "text/javascript",
    "text/css",
}


def _is_binary_content(ct: str | None) -> bool:
    """True for binary/static asset media types (images, audio, video, fonts...)."""
    if not ct:
        return False
    if ct.startswith(("image/", "audio/", "video/", "font/")):
        return True
    return ct in _BINARY_TYPES


def _is_json_content(ct: str | None) -> bool:
    """JSON content type: application/json or any *+json media type."""
    if not ct:
        return False
    return ct == "application/json" or ct.endswith("+json")


def _is_xml_content(ct: str | None) -> bool:
    if not ct:
        return False
    return ct in {"application/xml", "text/xml"} or ct.endswith("+xml")


class EndpointAnalyzer:
    """Analyze endpoint candidates from discovery output with safe GET requests."""

    def __init__(
        self,
        timeout: float = 10,
        base_url: str | None = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_response_size: int = 1_000_000,
        request_delay: float = 0.1,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
        if max_response_size <= 0:
            raise ValueError("max_response_size must be > 0")
        if request_delay < 0:
            raise ValueError("request_delay must be >= 0")

        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.follow_redirects = bool(follow_redirects)
        self.max_redirects = int(max_redirects)
        self.max_response_size = int(max_response_size)
        self.request_delay = float(request_delay)

        # Resolve optional fallback base URL for relative candidates.
        self.base_url: str | None = None
        if base_url is not None:
            parsed = self._parse_http_url(str(base_url))
            if parsed is None:
                raise ValueError(f"invalid base_url: {base_url!r}")
            self.base_url = str(base_url).strip()

        self._session = requests.Session()
        # Never use environment proxies or implicit credentials.
        self._session.trust_env = False
        self._session.headers.update({
            "User-Agent": "API-Endpoint-Analyzer/1.0",
            "Accept": "application/json, */*;q=0.8",
        })
        self._last_request_end: float | None = None
        # Fallback base URL taken from a discovery wrapper's "target" field.
        self._wrapper_target: str | None = None

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP session."""
        try:
            self._session.close()
        except Exception:  # pragma: no cover - best effort cleanup
            pass

    def __enter__(self) -> "EndpointAnalyzer":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- public analysis API ------------------------------------------------

    def analyze_endpoint(self, candidate: Any) -> dict[str, Any]:
        """Analyze one candidate; never raises, always returns a result record."""
        result = self._new_result()
        try:
            self._analyze_into(result, candidate)
        except Exception as exc:  # final fallback only; never BaseException
            logger.debug("unexpected error while analyzing endpoint")
            result["error"] = {
                "type": "unexpected_error",
                "message": f"{type(exc).__name__}: {exc}",
            }
        return result

    def analyze_candidates(self, candidates: Any) -> list[dict[str, Any]]:
        """Analyze many candidates; accepts list/dict wrapper/single item/None."""
        items: list[Any]
        if candidates is None:
            items = []
        elif isinstance(candidates, list):
            items = candidates
        elif isinstance(candidates, dict):
            inner = candidates.get("endpoints")
            if isinstance(inner, list):
                # Wrapper object: its target acts as fallback base URL.
                target = candidates.get("target")
                if isinstance(target, str) and target.strip():
                    self._wrapper_target = target.strip()
                items = inner
            else:
                items = [candidates]
        else:
            items = [candidates]
        return [self.analyze_endpoint(item) for item in items]

    def analyze_discovery_file(
        self,
        input_path: str,
        output_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load a discovery JSON file, analyze it, optionally write results.

        Raises ValueError for invalid JSON / wrong top-level shape, and lets
        OSError (e.g. FileNotFoundError) propagate.
        """
        with open(input_path, encoding="utf-8") as fh:
            raw = fh.read()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {input_path}: {exc}") from exc

        if isinstance(data, dict):
            endpoints = data.get("endpoints")
            if not isinstance(endpoints, list):
                raise ValueError("discovery JSON must contain an 'endpoints' list")
        elif isinstance(data, list):
            endpoints = data
        else:
            raise ValueError("discovery JSON must be an object or a list")

        results = self.analyze_candidates(data)

        if output_path is not None:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2, ensure_ascii=False)
        return results

    # -- core per-candidate flow --------------------------------------------

    def _analyze_into(self, result: dict[str, Any], candidate: Any) -> None:
        # ---- 1. Normalize the input item -------------------------------
        url_raw: Any = None
        source = SOURCE_DEFAULT
        sources: list[str] = [SOURCE_DEFAULT]
        found_in: list[str] | None = None
        if isinstance(candidate, str):
            url_raw = candidate
        elif isinstance(candidate, dict):
            url_raw = candidate.get("url")
            src = candidate.get("source")
            if isinstance(src, str) and src.strip():
                source = src
            raw_sources = candidate.get("sources")
            if isinstance(raw_sources, list):
                cleaned_sources = [s for s in raw_sources if isinstance(s, str) and s.strip()]
                if cleaned_sources:
                    # Dedupe, keep order; ensure primary source is first.
                    merged = ([source] if source not in cleaned_sources else []) + cleaned_sources
                    seen: set[str] = set()
                    sources = [s for s in merged if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]
                else:
                    sources = [source]
            else:
                sources = [source]
            fi = candidate.get("found_in")
            if isinstance(fi, list):
                strings = [e for e in fi if isinstance(e, str)]
                if strings:
                    found_in = [
                        self._truncate(self._redact_url_string(s), FOUND_IN_TRUNCATE)
                        for s in strings[:MAX_FOUND_IN]
                    ]
        result["source"] = source
        result["sources"] = sources
        if not isinstance(url_raw, str) or not url_raw.strip():
            result["error"] = {
                "type": "invalid_url",
                "message": "candidate has no usable URL string",
            }
            return

        # ---- 2. Clean / resolve / validate the URL (no request yet) ----
        cleaned = url_raw.strip()
        if "&amp;" in cleaned.lower():
            cleaned = html.unescape(cleaned)
            result["warnings"].append(
                "url contained HTML-escaped '&amp;'; decoded before analysis"
            )

        # The returned url is the cleaned/redacted form of the INPUT URL, with
        # any HTML-entity decoding already applied.  It is recorded BEFORE any
        # validation so it also appears on invalid-input error records.
        result["url"] = self._redact_url_string(cleaned)

        base = self.base_url or self._wrapper_target
        # Bare tokens with no scheme, authority or path ("not a url") are
        # rejected outright instead of being silently resolved against a base.
        try:
            probe = urlsplit(cleaned)
        except (ValueError, UnicodeError):
            probe = None
        if (
            probe is not None
            and not probe.scheme
            and not probe.netloc
            and not cleaned.startswith("/")
        ):
            result["error"] = {
                "type": "invalid_url",
                "message": "candidate is not an absolute or relative URL",
            }
            return
        try:
            resolved = self._resolve_url(cleaned, base)
        except (ValueError, UnicodeError):
            resolved = None
        if resolved is None:
            result["error"] = {
                "type": "invalid_url",
                "message": "URL could not be parsed or resolved",
            }
            return
        error = self._validate_resolved(resolved)
        if error is not None:
            result["error"] = error
            return

        # Extract parameters from the VISIBLE input query before sanitizing,
        # then blank sensitive values so they are never put on the wire.
        visible_url = self._rebuild(resolved)
        result["parameters"] = self._extract_parameters(visible_url)
        request_url, _sent_query, changed = self._sanitize_query(visible_url)
        if changed:
            result["warnings"].append("sensitive parameter values were not sent")

        # ---- 4. Safe GET request with manual redirect handling ---------
        # response_time_ms spans from just before the first request to the end
        # of the final body read; request_delay sleeps are excluded because the
        # timer starts after throttling and stops when the body read finishes.
        net = self._perform_request(result, request_url)
        if net is not None:
            result["response_time_ms"] = round(net["elapsed_s"] * 1000, 1)

        # ---- 5. Post-response analysis ----------------------------------
        if net is not None:
            self._finalize(result, net, request_url)

    # -- URL helpers ---------------------------------------------------------

    @staticmethod
    def _parse_http_url(url: str) -> tuple[str, str, str, str, str] | None:
        """Split a URL into components; return None on parsing failure."""
        try:
            parts = urlsplit(url.strip())
        except (ValueError, UnicodeError):
            return None
        if parts.scheme.lower() not in ("http", "https"):
            return None
        try:
            _ = parts.port  # forces validation of the port component
        except ValueError:
            return None
        if not parts.hostname:
            return None
        return (parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment)

    def _resolve_url(self, url: str, base: str | None) -> tuple[str, str, str, str, str] | None:
        """Resolve relative URLs against base; return split components or None."""
        candidate = url
        if base and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", url):
            candidate = urljoin(base, url)
        try:
            parts = urlsplit(candidate)
            _ = parts.port  # validates the port component early
        except (ValueError, UnicodeError):
            return None
        scheme = parts.scheme.lower()
        if not parts.scheme and not parts.netloc:
            # Still relative (no base available) -> cannot be requested.
            return None
        if scheme not in ("http", "https") and not parts.netloc:
            # Opaque scheme-specific URL (e.g. javascript:alert(1)).  Return it
            # with the scheme in the netloc slot so the validator reports
            # unsupported_scheme rather than a generic parse failure.
            return (scheme, "", parts.path, parts.query, "")
        # Non-http(s) schemes are passed through so the validator can report
        # unsupported_scheme instead of a generic parse failure.
        return (scheme, parts.netloc, parts.path, parts.query, "")

    @staticmethod
    def _validate_resolved(
        parts: tuple[str, str, str, str, str]
    ) -> dict[str, str] | None:
        """Scheme / hostname / userinfo checks performed BEFORE any request."""
        candidate = urlunsplit(parts)
        try:
            split = urlsplit(candidate)
            scheme = split.scheme.lower()
            host = (split.hostname or "").lower()
            userinfo = split.username is not None or split.password is not None
        except (ValueError, UnicodeError):
            return {"type": "invalid_url",
                    "message": "URL could not be parsed safely"}
        if scheme not in ("http", "https"):
            return {
                "type": "unsupported_scheme",
                "message": f"URL scheme '{scheme or 'none'}' is not supported "
                           "(http/https only)",
            }
        if not host:
            return {"type": "invalid_url", "message": "URL has no hostname"}
        if userinfo:
            return {
                "type": "invalid_url",
                "message": "URL contains userinfo which is rejected",
            }
        return None

    @staticmethod
    def _rebuild(parts: tuple[str, str, str, str, str]) -> str:
        scheme, netloc, path, query, _frag = parts
        return urlunsplit((scheme, netloc, path, query, ""))

    def _is_sensitive_key(self, key: str) -> bool:
        """Normalize then substring-match against sensitive patterns."""
        try:
            decoded = unquote(key)
        except Exception:
            decoded = key
        norm = decoded.lower().replace("-", "").replace("_", "")
        return any(p in norm for p in SENSITIVE_PATTERNS)

    def _sanitize_query(self, url: str) -> tuple[str, bool, bool]:
        """Blank sensitive query values for the initial request.

        Returns (request_url, sanitized_query_or_None, changed).
        """
        parts = urlsplit(url)
        if not parts.query:
            return url, None, False
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        changed = False
        out: list[str] = []
        for name, value in pairs:
            if self._is_sensitive_key(name) and value:
                out.append(f"{quote(name, safe='')}=")
                changed = True
            else:
                out.append(f"{quote(name, safe='')}={quote(value, safe='')}")
        new_query = "&".join(out)
        rebuilt = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))
        return rebuilt, new_query, changed

    def _redact_url_string(self, url: str) -> str:
        """Redact sensitive query values inside any URL-like string."""
        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return url
        if not parts.query:
            return url
        out = []
        for pair in parts.query.split("&"):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            if self._is_sensitive_key(name) and value:
                out.append(f"{name}={REDACTED}")
            else:
                out.append(pair)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(out), parts.fragment))

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        return text if len(text) <= limit else text[:limit]

    @staticmethod
    def _safe_log_url(url: str) -> str:
        """Only scheme/host/path for logging - never query strings."""
        try:
            p = urlsplit(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except (ValueError, UnicodeError):
            return "<unparseable-url>"

    # -- networking ----------------------------------------------------------

    def _throttle(self) -> None:
        """Enforce request_delay between network requests (not before the first)."""
        if self._last_request_end is None or self.request_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_end
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _mark_request_done(self) -> None:
        self._last_request_end = time.monotonic()

    def _perform_request(
        self,
        result: dict[str, Any],
        initial_url: str,
    ) -> dict[str, Any] | None:
        """Manual-redirect GET loop. Returns observed network data or None on error."""
        current_url = initial_url
        chain: list[str] = [initial_url]
        redirect_host = self._redirect_host(initial_url)
        hops = 0
        connect_s = 0.0   # request/response-header time, excluding throttle sleeps
        body_s = 0.0      # accumulated body-read time

        while True:
            self._throttle()               # delay sleeps happen outside the timer
            logger.debug("requesting %s", self._safe_log_url(current_url))
            t_conn0 = time.perf_counter()
            try:
                response = self._session.get(
                    current_url,
                    allow_redirects=False,
                    stream=True,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except Timeout as exc:
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {"type": "timeout", "message": self._short(str(exc))}
                return None
            except SSLError as exc:
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {"type": "ssl_error", "message": self._short(str(exc))}
                return None
            except (InvalidURL, InvalidSchema, MissingSchema) as exc:
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {"type": "invalid_url", "message": self._short(str(exc))}
                return None
            except RequestsConnectionError as exc:
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {"type": "connection_error", "message": self._short(str(exc))}
                return None
            except RequestException as exc:
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {"type": "request_error", "message": self._short(str(exc))}
                return None
            except Exception as exc:  # unexpected network-layer failure
                self._mark_request_done()
                result["method"] = "GET"
                result["final_url"] = self._redact_url_string(chain[-1])
                result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
                result["redirected"] = len(chain) > 1
                result["error"] = {
                    "type": "unexpected_error",
                    "message": f"{type(exc).__name__}: {self._short(str(exc))}",
                }
                return None

            connect_s += time.perf_counter() - t_conn0
            try:
                status = response.status_code
                headers = {k.lower(): v for k, v in response.headers.items()}
                content_type = self._normalize_content_type(headers.get("content-type"))
                location = headers.get("location")

                is_redirect = status in REDIRECT_STATUSES and bool(location and location.strip())

                if is_redirect and self.follow_redirects:
                    if hops >= self.max_redirects:
                        # Too many redirects: stop, keep this response info.
                        t_body0 = time.perf_counter()
                        observed = self._read_body(response, headers, content_type, result)
                        body_s += time.perf_counter() - t_body0
                        observed["status"] = status
                        observed["final_url"] = current_url
                        observed["chain"] = chain
                        observed["blocked"] = False
                        observed["too_many"] = True
                        observed["location"] = location
                        observed["elapsed_s"] = connect_s + body_s
                        return observed
                    nxt, blocked_reason = self._resolve_redirect(current_url, location, redirect_host)
                    if nxt is None:
                        # Blocked redirect: NEVER request the target. Preserve
                        # the header-level information of this 3xx response;
                        # the body is not inspected (response_structure stays
                        # null because no body could be inspected safely).
                        observed = {
                            "headers": headers,
                            "content_type": content_type,
                            "body": None,   # body deliberately not inspected
                            "size": None,
                            "truncated": False,
                            "deadline": False,
                        }
                        observed["status"] = status
                        # final_url = last URL actually requested (never the
                        # blocked/unrequested redirect target).
                        observed["final_url"] = chain[-1]
                        observed["chain"] = chain
                        observed["blocked"] = True
                        observed["too_many"] = False
                        observed["block_reason"] = blocked_reason or "redirect target blocked"
                        observed["location"] = location
                        observed["elapsed_s"] = connect_s + body_s
                        return observed
                    # Follow: read/discard body to free connection, then hop.
                    try:
                        response.close()
                    finally:
                        self._mark_request_done()
                    nxt_request, _, hop_changed = self._sanitize_query(nxt)
                    if hop_changed:
                        result["warnings"].append(
                            "sensitive parameter values were not sent"
                        )
                    current_url = nxt_request
                    chain.append(nxt_request)
                    hops += 1
                    continue

                # Final response for this candidate.
                t_body0 = time.perf_counter()
                observed = self._read_body(response, headers, content_type, result)
                body_s += time.perf_counter() - t_body0
                observed["status"] = status
                observed["final_url"] = current_url
                observed["chain"] = chain
                observed["blocked"] = False
                observed["too_many"] = False
                observed["location"] = location
                observed["elapsed_s"] = connect_s + body_s
                if status in REDIRECT_STATUSES and not (location and location.strip()):
                    result["warnings"].append("redirect without Location")
                return observed
            finally:
                try:
                    response.close()
                except Exception:
                    pass
                # Cookies must never carry between candidates or hops.
                try:
                    self._session.cookies.clear()
                except Exception:
                    pass

    @staticmethod
    def _short(message: str) -> str:
        message = message.replace("\n", " ").strip()
        return message[:200] or "request failed"

    def _redirect_host(self, url: str) -> tuple[str, str, int] | None:
        """(scheme, normalized-host, effective-port) used for same-host checks."""
        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return None
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        try:
            port = parts.port
        except ValueError:
            return None
        if port is None:
            port = 443 if parts.scheme.lower() == "https" else 80
        return (parts.scheme.lower(), host, port)

    def _resolve_redirect(
        self, current_url: str, location: str, origin: tuple[str, str, int] | None
    ) -> tuple[str | None, str | None]:
        """Validate a redirect target; return (url, None) or (None, reason)."""
        try:
            target = urljoin(current_url, location.strip())
            parts = urlsplit(target)
        except (ValueError, UnicodeError):
            return None, "redirect target could not be parsed"
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return None, "redirect target uses an unsupported scheme"
        if parts.username is not None or parts.password is not None:
            return None, "redirect target contains userinfo"
        try:
            tport = parts.port
        except ValueError:
            return None, "redirect target has an invalid port"
        thost = (parts.hostname or "").lower()
        if thost.startswith("www."):
            thost = thost[4:]
        if not thost:
            return None, "redirect target has no hostname"
        if tport is None:
            tport = 443 if scheme == "https" else 80
        if origin is not None:
            oscheme, ohost, oport = origin
            if thost != ohost:
                return None, "redirect target is on a different host"
            if scheme != oscheme:
                # Allow http -> https upgrade only when both use default ports.
                if not (oscheme == "http" and scheme == "https"
                        and oport == 80 and tport == 443):
                    return None, "redirect target changes scheme"
            if tport != oport and not (oscheme == "http" and scheme == "https"
                                       and oport == 80 and tport == 443):
                return None, "redirect target changes port"
        # Rebuild without fragment; keep everything else as resolved.
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")), None

    # -- body reading --------------------------------------------------------

    def _read_body(
        self,
        response: requests.Response,
        headers: dict[str, str],
        content_type: str | None,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Read up to max_response_size bytes with a total deadline of timeout."""
        decoded_size = 0
        truncated = False
        deadline_exceeded = False
        chunks: list[str] = []
        collected = 0
        decoder_used = False
        deadline = time.monotonic() + self.timeout
        try:
            for raw in response.iter_content(chunk_size=CHUNK_SIZE):
                if not raw:
                    continue
                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break
                remaining = self.max_response_size - decoded_size
                if len(raw) > remaining:
                    raw = raw[:remaining]
                    truncated = True
                piece = raw.decode("utf-8-sig", errors="replace")
                decoded_size += len(piece)
                if collected < BODY_READ_LIMIT:
                    chunks.append(piece[: BODY_READ_LIMIT - collected])
                    collected += min(len(piece), BODY_READ_LIMIT - collected)
                decoder_used = True
                if truncated:
                    break
                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break
        except Exception as exc:
            result["warnings"].append(
                f"body read interrupted: {type(exc).__name__}: {self._short(str(exc))}"
            )
        if truncated:
            result["warnings"].append(
                f"body truncated at {self.max_response_size} bytes"
            )
        if deadline_exceeded:
            result["warnings"].append("body read deadline exceeded")
        body = "".join(chunks)
        return {
            "headers": headers,
            "content_type": content_type,
            "body": body,
            "size": decoded_size,
            "truncated": truncated,
            "deadline": deadline_exceeded,
            "decoder_used": decoder_used,
        }

    # -- post-response finalization ------------------------------------------

    def _finalize(
        self,
        result: dict[str, Any],
        net: dict[str, Any],
        initial_url: str,
    ) -> None:
        headers: dict[str, str] = net["headers"]
        content_type: str | None = net["content_type"]
        status: int = net["status"]
        body: str = net["body"]
        chain: list[str] = net["chain"]
        final_url: str = net["final_url"]

        result["method"] = "GET"
        result["status"] = status
        result["status_category"] = f"{status // 100}xx"
        result["content_type"] = content_type
        result["response_size"] = net["size"]
        result["response_size_truncated"] = bool(net["truncated"])

        # Redirect bookkeeping.
        result["redirected"] = len(chain) > 1
        result["redirect_chain"] = [self._redact_url_string(u) for u in chain]
        result["final_url"] = self._redact_url_string(final_url)

        # Selected headers.
        result["headers"] = self._extract_headers(headers)

        # Path parameters from the FINAL requested URL path (query parameters
        # were already extracted from the visible input URL).
        result["parameters"] = result["parameters"] + self._path_parameters(final_url)

        # Response structure.  A null body means the body could not be
        # inspected (e.g. a blocked-redirect response that was deliberately
        # not read), so response_structure stays null in that case.
        if body is None:
            struct: dict[str, Any] | None = None
        else:
            struct = self._detect_structure(body, content_type, net, result)
        result["response_structure"] = struct

        # Warnings for missing content type.
        if content_type is None:
            result["warnings"].append("missing Content-Type header")

        # Classifications.
        ctx = {
            "status": status,
            "content_type": content_type,
            "struct": struct,
            "body": body,
            "headers": headers,
            "chain": chain,
            "final_url": final_url,
            "initial_url": initial_url,
            "truncated": net["truncated"],
            "deadline": net.get("deadline", False),
            "followed_same_host": len(chain) > 1,
        }
        result["api_behavior"] = self._classify_api_behavior(ctx)
        result["access"] = self._classify_access(ctx)

        # Redirect-related errors.
        if net.get("blocked"):
            result["error"] = {
                "type": "blocked_redirect",
                "message": net.get("block_reason", "redirect target blocked"),
            }
        elif net.get("too_many"):
            result["error"] = {
                "type": "too_many_redirects",
                "message": f"more than {self.max_redirects} redirects encountered",
            }

    @staticmethod
    def _normalize_content_type(value: str | None) -> str | None:
        if value is None:
            return None
        ct = value.strip().lower()
        if not ct:
            return None
        return ct.split(";", 1)[0].strip() or None

    def _extract_headers(self, headers: dict[str, str]) -> dict[str, str | None]:
        wanted = (
            "content-length", "server", "allow", "www-authenticate",
            "location", "access-control-allow-origin",
        )
        out: dict[str, str | None] = {}
        for key in wanted:
            value = headers.get(key)
            if value is None:
                out[key] = None
                continue
            value = value.strip()
            if key == "location":
                value = self._redact_url_string(value)
            out[key] = self._truncate(value, MAX_HEADER_VALUE)
        return out

    # -- parameters ------------------------------------------------------------

    def _extract_parameters(self, url: str) -> list[dict[str, Any]]:
        """Visible query parameters (first occurrence per name, sensitive redacted)."""
        try:
            query = urlsplit(url).query
        except (ValueError, UnicodeError):
            return []
        seen: set[str] = set()
        params: list[dict[str, Any]] = []
        for name, value in parse_qsl(query, keep_blank_values=True):
            if name in seen:
                continue
            seen.add(name)
            if self._is_sensitive_key(name):
                example: str = REDACTED
            else:
                example = self._truncate(value, MAX_PARAM_EXAMPLE)
            params.append({
                "name": name,
                "location": "query",
                "example_value": example,
            })
        return params

    def _path_parameters(self, url: str) -> list[dict[str, Any]]:
        """Obvious numeric-ID / UUID path segments (names are not invented)."""
        try:
            path = urlsplit(url).path
        except (ValueError, UnicodeError):
            return []
        out: list[dict[str, Any]] = []
        try:
            segments = [s for s in path.split("/") if s]
        except Exception:
            return []
        for idx, seg in enumerate(segments):
            kind = None
            if NUMERIC_SEG_RE.fullmatch(seg):
                kind = "possible_identifier"
            elif UUID_SEG_RE.fullmatch(seg):
                kind = "possible_identifier"
            if kind:
                out.append({
                    "name": None,
                    "location": "path",
                    "segment": self._truncate(seg, MAX_PARAM_EXAMPLE),
                    "position": idx,
                    "parameter_type": kind,
                })
        return out

    # -- response structure ----------------------------------------------------

    def _looks_like_html(self, body: str) -> bool:
        head = body.lstrip()[:200].lower()
        return head.startswith("<!doctype html") or head.startswith("<html")

    def _try_parse_json(self, text: str) -> tuple[bool, Any]:
        try:
            return True, json.loads(text)
        except RecursionError:
            return False, None
        except (ValueError, TypeError):
            return False, None
        except Exception:
            return False, None

    def _detect_structure(
        self,
        body: str,
        content_type: str | None,
        net: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """FIRST MATCH WINS detection per spec section 10."""
        # A null body means no body could be inspected at all (e.g. a blocked
        # redirect response that was deliberately not read).
        if body is None:
            return None
        stripped = body.strip()
        # 1. empty body
        if not stripped:
            if _is_json_content(content_type):
                result["warnings"].append("empty JSON body")
            return {"type": "empty"}
        # 2. binary/static
        if _is_binary_content(content_type):
            return {"type": "binary"}
        json_ct = _is_json_content(content_type)
        # 3. JSON
        starts_json = stripped[0] in "{["
        if json_ct or starts_json:
            ok, parsed = self._try_parse_json(stripped)
            if ok:
                if not json_ct and (isinstance(parsed, (dict, list))):
                    result["warnings"].append(
                        f"JSON despite content type {content_type or 'unknown'}"
                    )
                struct = self._infer_structure(parsed, 1)
                feats = self._detect_features(parsed)
                if feats["pagination_indicators"] or feats["data_wrapper"]:
                    struct["features"] = feats
                return struct
            # JSON-ish but failed to parse
            if json_ct:
                if net["truncated"] or net["deadline"]:
                    # incomplete body: don't classify as malformed
                    return {"type": "unknown"}
                if self._looks_like_html(stripped):
                    if _is_xml_content(content_type):
                        return {"type": "xml"}
                    return {"type": "html"}
                result["warnings"].append("malformed JSON")
                return {"type": "unknown"}
            # non-JSON CT, looked like JSON but did not parse -> fall through
        # 4. XML
        if _is_xml_content(content_type) or stripped.lower().startswith("<?xml"):
            return {"type": "xml"}
        # 5. HTML
        if content_type == "text/html" or self._looks_like_html(stripped):
            return {"type": "html"}
        # 6. Text
        if (content_type or "").startswith("text/") or content_type in _JS_CSS_TYPES:
            return {"type": "text"}
        # 7. unknown
        return {"type": "unknown"}

    def _primitive_type(self, value: Any) -> str:
        # bool must be checked BEFORE int (bool subclasses int).
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        return "unknown"

    def _infer_structure(self, value: Any, depth: int = 1) -> dict[str, Any]:
        """Infer a compact JSON schema down to MAX_SCHEMA_DEPTH.

        Object nodes record their keys and recurse into nested objects/arrays
        until the depth limit; array nodes record length, item type(s) and,
        when inspected items are objects, their union of keys.
        """
        if isinstance(value, dict):
            keys = list(value.keys())
            struct: dict[str, Any] = {"type": "object", "keys": keys[:MAX_KEYS_PER_OBJECT]}
            if len(keys) > MAX_KEYS_PER_OBJECT:
                struct["note"] = f"only first {MAX_KEYS_PER_OBJECT} keys recorded"
            nested: dict[str, Any] = {}
            if depth < MAX_SCHEMA_DEPTH:
                for key in keys[:MAX_KEYS_PER_OBJECT]:
                    child = value[key]
                    if isinstance(child, (dict, list)):
                        nested[str(key)] = self._infer_structure(child, depth + 1)
            if nested:
                struct["nested"] = nested
            return struct
        if isinstance(value, list):
            struct = {
                "type": "array",
                "length": len(value),
                "item_type": None,
            }
            if value:
                inspected = value[:MAX_ARRAY_ITEMS_TO_INSPECT]
                types = []
                for item in inspected:
                    if isinstance(item, dict):
                        types.append("object")
                    elif isinstance(item, list):
                        types.append("array")
                    else:
                        types.append(self._primitive_type(item))
                unique = sorted(set(types))
                if len(unique) == 1:
                    struct["item_type"] = unique[0]
                else:
                    struct["item_type"] = "mixed"
                    struct["item_types"] = unique
                obj_keys: list[str] = []
                seen: set[str] = set()
                for item in inspected:
                    if isinstance(item, dict):
                        for key in item.keys():
                            if key not in seen:
                                seen.add(key)
                                obj_keys.append(key)
                if obj_keys:
                    struct["item_keys"] = obj_keys[:MAX_KEYS_PER_OBJECT]
            return struct
        return {"type": self._primitive_type(value)}

    def _detect_features(self, value: Any) -> dict[str, Any]:
        indicators = []
        wrapper = None
        if isinstance(value, dict):
            lowered = {str(k).lower() for k in value.keys()}
            indicators = [f for f in PAGINATION_FIELDS if f in lowered]
            for w in DATA_WRAPPERS:
                if w in lowered:
                    wrapper = w
                    break
        return {"pagination_indicators": indicators, "data_wrapper": wrapper}

    # -- classification --------------------------------------------------------

    def _parsed_container(self, struct: dict[str, Any] | None) -> bool:
        return isinstance(struct, dict) and struct.get("type") in ("object", "array")

    def _classify_api_behavior(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """FIRST MATCH WINS rules from spec section 15."""
        ev: list[str]
        struct = ctx["struct"]
        ct = ctx["content_type"]
        status = ctx["status"]
        body = ctx["body"]
        headers = ctx["headers"]
        json_ct = _is_json_content(ct)
        container = self._parsed_container(struct)
        primitive_json = (
            isinstance(struct, dict)
            and struct.get("type") in ("string", "number", "boolean", "null")
            and json_ct
        )
        stype = struct.get("type") if isinstance(struct, dict) else None

        # 1. request failed (or no response body could be inspected)
        if stype is None:
            return self._behavior(
                "uncertain", ["1: request failed or response body unavailable"]
            )
        # 2. JSON object/array + JSON content type + not 404/410
        if container and json_ct and status not in (404, 410):
            return self._behavior(
                "confirmed",
                [f"2: JSON {stype} returned with JSON content type (status {status})"],
            )
        # 3. JSON object/array with 404/410
        if container and status in (404, 410):
            return self._behavior(
                "likely",
                [f"3: JSON {stype} returned with error status {status}"],
            )
        # 4. JSON primitive with JSON content type
        if primitive_json:
            return self._behavior("likely", ["4: JSON primitive with JSON content type"])
        # 5. truncated body that looks like JSON
        if (ctx["truncated"] or ctx.get("deadline")) and (
            json_ct or body.lstrip()[:1] in "{["
        ):
            return self._behavior(
                "likely", ["5: body truncated while looking like JSON"]
            )
        # 6. JSON content type + malformed non-HTML body
        if json_ct and stype == "unknown":
            return self._behavior(
                "likely", ["6: JSON content type but body could not be parsed"]
            )
        # 7. JSON content type + empty body
        if json_ct and stype == "empty":
            return self._behavior("uncertain", ["7: JSON content type with empty body"])
        # 8. valid JSON object/array with non-JSON content type
        if container and not json_ct:
            return self._behavior(
                "likely", [f"8: JSON {stype} served with non-JSON content type"]
            )
        # 9. static/binary asset or JavaScript/CSS
        if stype == "binary" or ct in _JS_CSS_TYPES:
            return self._behavior("unlikely", ["9: static/binary asset response"])
        # 10. XML
        if stype == "xml":
            return self._behavior("likely", ["10: XML response"])
        # 11. 401/403/405 with non-HTML body and auth/allow hints
        if status in (401, 403, 405) and stype != "html" and (
            headers.get("www-authenticate") or headers.get("allow")
        ):
            evidence = [f"11: status {status} with machine-readable error response"]
            if headers.get("www-authenticate"):
                evidence.append("11: WWW-Authenticate header present")
            if headers.get("allow"):
                evidence.append("11: Allow header present")
            return self._behavior("likely", evidence)
        # 12. same-host redirect followed to a login/auth path
        if ctx["followed_same_host"] and LOGIN_PATH_RE.search(self._path_of(ctx["final_url"])):
            return self._behavior(
                "uncertain", ["12: redirected to a login/authentication path"]
            )
        # 13. any other 401/403/405
        if status in (401, 403, 405):
            return self._behavior(
                "uncertain", [f"13: status {status} indicates restricted access"]
            )
        # 14. clearly HTML
        if stype == "html":
            return self._behavior("unlikely", ["14: HTML page response"])
        # 15. anything else
        return self._behavior("uncertain", ["15: insufficient evidence to classify"])

    @staticmethod
    def _behavior(classification: str, evidence: list[str]) -> dict[str, Any]:
        return {"classification": classification, "evidence": evidence}

    def _path_of(self, url: str) -> str:
        try:
            return urlsplit(url).path or ""
        except (ValueError, UnicodeError):
            return ""

    def _classify_access(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """FIRST MATCH WINS rules from spec section 16."""
        status = ctx["status"]
        headers = ctx["headers"]
        ev: list[str]
        # 1. authentication required
        if status == 401 or headers.get("www-authenticate"):
            ev = []
            if status == 401:
                ev.append("1: status 401 Unauthorized")
            if headers.get("www-authenticate"):
                ev.append("1: WWW-Authenticate header present")
            return {"classification": "authentication_required", "evidence": ev}
        # 2. forbidden
        if status == 403:
            return {
                "classification": "forbidden",
                "evidence": ["2: status 403 Forbidden"],
            }
        # 3. same-host redirect to login/auth path
        if ctx["followed_same_host"] and LOGIN_PATH_RE.search(self._path_of(ctx["final_url"])):
            return {
                "classification": "authentication_required",
                "evidence": ["3: redirected to a login/authentication path"],
            }
        # 4. 2xx without analyzer-supplied credentials
        if 200 <= status < 300:
            return {
                "classification": "public",
                "evidence": ["4: 2xx response without supplied credentials"],
            }
        # 5. everything else
        return {"classification": "unknown", "evidence": ["5: no access signal matched"]}

    # -- result scaffolding ------------------------------------------------------

    @staticmethod
    def _new_result() -> dict[str, Any]:
        """Canonical single-schema result with neutral defaults."""
        return {
            "url": None,
            "source": SOURCE_DEFAULT,
            "sources": [SOURCE_DEFAULT],
            "found_in": None,
            "method": None,
            "status": None,
            "status_category": None,
            "content_type": None,
            "parameters": [],
            "response_structure": None,
            "final_url": None,
            "redirected": False,
            "redirect_chain": [],
            "response_time_ms": None,
            "response_size": None,
            "response_size_truncated": False,
            "headers": {
                "content-length": None,
                "server": None,
                "allow": None,
                "www-authenticate": None,
                "location": None,
                "access-control-allow-origin": None,
            },
            "api_behavior": {"classification": "uncertain", "evidence": []},
            "access": {"classification": "unknown", "evidence": []},
            "warnings": [],
            "error": None,
        }


# ---------------------------------------------------------------------------
# Convenience function and minimal entry point
# ---------------------------------------------------------------------------

def analyze_discovery_file(
    input_path: str,
    output_path: str | None = None,
    **options: Any,
) -> list[dict[str, Any]]:
    """Build an EndpointAnalyzer(**options), analyze the file, always close."""
    analyzer = EndpointAnalyzer(**options)
    try:
        return analyzer.analyze_discovery_file(input_path, output_path)
    finally:
        analyzer.close()


def main(argv: list[str]) -> int:
    """Minimal entry point: python endpoint_analysis.py discovery.json [out.json]"""
    if len(argv) < 2:
        print("usage: python endpoint_analysis.py <discovery.json> [analysis.json]",
              file=sys.stderr)
        return 1
    input_path = argv[1]
    output_path = argv[2] if len(argv) > 2 else None
    try:
        results = analyze_discovery_file(input_path, output_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {type(exc).__name__}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    if output_path is None:
        print(json.dumps(results, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
