"""endpoint_analysis.py — safe characterization of discovered API endpoints.

Pipeline position:

    crawler.py -> endpoint_discovery.py -> discovery JSON
                -> endpoint_analysis.py (THIS MODULE) -> main.py / cli.py

Scope is strictly *endpoint analysis & validation*. This module does not
crawl, discover, fuzz, brute-force, or exploit. It issues a bounded number of
read-only HTTP requests (GET, optionally OPTIONS), never sends a request body,
and never performs a state-changing method.

Design rules that shape the code:

* One bad endpoint never breaks a batch. Every per-endpoint path is
  exception-guarded and returns a structured error instead of raising.
* Requests are bounded: configurable timeout, per-request delay, a hard
  response-size cap, and a redirect limit with loop detection.
* Display and transmission of sensitive data are SEPARATE concerns.
  `redact_sensitive` controls what the report shows; `send_sensitive_params`
  controls what leaves this machine. They are never coupled.
* Classifications are evidence-backed. `api_behavior` never promotes an
  endpoint to `confirmed` on a URL name or a JSON content type alone.
* Every claim this module makes is backed by a numbered evidence line, so a
  reader can check the reasoning instead of trusting the verdict.
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import re
import sys
import time
import xml.etree.ElementTree as ET
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
# Limits
# ---------------------------------------------------------------------------

MAX_SCHEMA_DEPTH = 4
MAX_KEYS_PER_OBJECT = 50
MAX_ARRAY_ITEMS_TO_INSPECT = 5
CHUNK_SIZE = 8192

# Maximum raw response bytes consumed per endpoint.
DEFAULT_MAX_RESPONSE_SIZE = 1_000_000

# Maximum decoded characters retained for structure inference. Separate from
# the raw-byte cap so pathological decoding cannot balloon memory.
BODY_READ_LIMIT = 1_000_000

MAX_PARAM_EXAMPLE = 40
MAX_HEADER_VALUE = 200
MAX_FOUND_IN = 5
FOUND_IN_TRUNCATE = 300
MAX_ERROR_MESSAGE = 200

# Bounds on sensitive-information reporting.
MAX_SENSITIVE_FINDINGS = 25
MAX_SENSITIVE_VALUE = 120
MAX_SECRET_SCAN_BYTES = 200_000
MAX_JSON_WALK_NODES = 2_000

REDACTED = "REDACTED"
SOURCE_DEFAULT = "endpoint_discovery"

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# ---------------------------------------------------------------------------
# Sensitive data identification
# ---------------------------------------------------------------------------

# Key-name fragments. Matched token-wise (see `_is_sensitive_key`) so
# "author" does not trip the "auth" fragment while "api_key", "authToken"
# and "password" still do.
#
# "code" is deliberately absent. On its own it is an envelope/status marker
# (`{"code": 0, "message": "ok"}`), and treating it as a secret made almost
# every API report a false "sensitive data exposed" finding plus a bogus
# caching warning. Real credential spellings still match on another token:
# `authorization_code` trips "authorization". A "code*" compound is not
# added here because the tokenizer splits on _/-/camelCase humps, so a
# multi-word compound could never match anything.
SENSITIVE_PATTERNS = (
    "token", "key", "secret", "password", "passwd", "pwd", "auth",
    "session", "cookie", "jwt", "signature", "credential",
)

# Single-word compounds the camelCase/separator tokenizer cannot split.
_SENSITIVE_COMPOUNDS = frozenset({
    "authorization", "authenticated", "authentication", "authenticator",
    "sessionid", "authtoken", "apikey", "secretkey", "clientsecret",
    "accesstoken", "refreshtoken", "idtoken", "csrftoken", "xsrftoken",
    "privatekey", "apikeys", "accesstokenid",
})

# High-confidence secret/token formats. Deliberately narrow: an arbitrary
# random string must not be reported as a secret.
_SECRET_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            r"\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
        ),
    ),
    (
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "bearer_token",
        re.compile(
            r"\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)", re.IGNORECASE
        ),
    ),
    (
        "basic_auth_header",
        re.compile(
            r"\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})", re.IGNORECASE
        ),
    ),
    (
        "credential_assignment",
        re.compile(
            r"\b(api[_-]?key|secret|token|password|passwd|"
            r"client[_-]?secret|access[_-]?key)\b\s*[=:]\s*"
            r"['\"]?([A-Za-z0-9_\-+/=.]{16,})['\"]?",
            re.IGNORECASE,
        ),
    ),
)

# Response headers whose *values* are credentials or session material. Used
# to redact the captured value and to keep the value out of the free-text
# secret scan (it is already reported on its own, with a better location).
_SENSITIVE_HEADERS = frozenset({
    "set-cookie", "set-cookie2", "authorization", "proxy-authorization",
    "www-authenticate", "x-api-key", "x-auth-token", "x-csrf-token",
    "x-xsrf-token", "x-amz-security-token", "x-access-token",
})

# A strict subset of the above: header *names* worth reporting as a finding
# even when the value looks opaque. It excludes `www-authenticate` (a scheme
# name, not a credential), `proxy-authorization` and `set-cookie2` (not
# meaningful in a normal response), which is why this is not simply
# `_SENSITIVE_HEADERS`.
_SENSITIVE_HEADER_NAMES = frozenset({
    "set-cookie", "authorization", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
})

# ---------------------------------------------------------------------------
# Content-type helpers
# ---------------------------------------------------------------------------

_BINARY_TYPES = {
    "application/pdf", "application/zip", "application/octet-stream",
    "application/wasm", "application/gzip", "application/x-gzip",
    "application/x-tar", "application/x-7z-compressed",
    "application/vnd.openxmlformats-officedocument",
}

_JS_CSS_TYPES = {
    "application/javascript", "application/x-javascript",
    "text/javascript", "text/css",
}

_TEXTUAL_TYPES = {
    "text/plain", "text/csv", "text/markdown", "text/yaml",
    "application/x-yaml", "application/yaml", "text/xml",
}

# Headers worth capturing. Deliberately curated: dumping every response
# header adds noise without aiding endpoint analysis.
_CAPTURED_HEADERS = (
    "content-type", "content-length", "content-encoding",
    "server", "allow", "www-authenticate", "location",
    "cache-control", "vary", "retry-after", "server-timing",
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options",
    "x-content-type-nosniff", "referrer-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-methods", "access-control-allow-headers",
    "access-control-expose-headers", "access-control-max-age",
    "x-powered-by", "x-request-id", "x-ratelimit-limit",
    "x-ratelimit-remaining", "x-ratelimit-reset",
    "etag", "last-modified", "age",
)

# ---------------------------------------------------------------------------
# Path / identifier patterns
# ---------------------------------------------------------------------------

LOGIN_PATH_RE = re.compile(
    r"(log-?in|sign-?in|logout|sign-?out|sso|saml|oauth2?|authorize"
    r"|authenticate|account/login)([/.?]|$)",
    re.I,
)
NUMERIC_SEG_RE = re.compile(r"\d+")
UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# MongoDB ObjectId: 24 hex characters. Reported as an identifier, not a secret.
OBJECTID_SEG_RE = re.compile(r"[0-9a-fA-F]{24}")
HEX_SEG_RE = re.compile(r"[0-9a-fA-F]{8,}")

# A path component that an API usually lives under. Segment-anchored so
# /capital and /apiary do not match, while /api-docs and /api/v1 do.
_API_PATH_RE = re.compile(
    r"(?:^|/)(?:api|v\d+|rest|graphql|graphiql|resources|rpc|wsdl|soap"
    r"|webhooks?)(?:[/\-_.]|$)",
    re.I,
)

# Splits a key into words on separators and camelCase humps, so "api_key"
# yields ["api","key"] and "authToken" yields ["auth","Token"].
_KEY_TOKENS_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")

# ---------------------------------------------------------------------------
# JSON body signals
# ---------------------------------------------------------------------------

# JSON keys that mark a machine-readable API error envelope. The "strong"
# set stands alone; the "supporting" set only counts on a 4xx/5xx status
# because "message"/"title" are far too common to trust in a 200 response.
_ERROR_KEYS_STRONG = frozenset({
    "statuscode", "status_code", "errorcode", "error_code", "errcode",
    "err_code", "faultcode", "fault_string", "faultstring", "apierror",
    "errormessage", "error_message",
})
_ERROR_KEYS_SUPPORTING = frozenset({
    "error", "errors", "message", "detail", "details", "reason", "title",
    "instance", "problem", "denied", "unauthorized", "forbidden",
})

# Pagination fields. Presence indicates a list-returning API.
_PAGINATION_KEYS = frozenset({
    "page", "page_number", "pagenumber", "page_index", "per_page",
    "perpage", "page_size", "pagesize", "limit", "offset", "skip", "take",
    "start", "startindex", "cursor", "nextcursor", "after", "before",
    "total", "total_count", "totalcount", "total_pages", "totalpages",
    "count", "has_more", "hasmore", "has_next", "hasnext",
    "next", "next_page", "nextpage", "prev", "previous", "previous_page",
    "previouspage", "num_results", "numresults", "size",
})

# Envelope keys wrapping the actual payload.
_DATA_WRAPPER_KEYS = frozenset({
    "data", "results", "items", "records", "rows", "entries", "list",
    "collection", "content", "payload", "resources", "values", "elements",
})

# HTTP statuses where a machine-readable body is an API error contract.
_API_ERROR_STATUSES = (400, 401, 403, 404, 405, 406, 409, 410, 415,
                       422, 429, 500, 501, 502, 503)
_AUTH_STATUSES = (401, 403, 405)
# 404/410 bodies are generic miss handlers on most frameworks, so an
# envelope there needs an API-specific key to count.
_GENERIC_MISS_STATUSES = (404, 410)

# A served OpenAPI/Swagger document declares an API surface outright.
_SPEC_VERSION_KEYS = frozenset({"openapi", "swagger"})
_SPEC_PATHS_KEY = "paths"

# Classification thresholds.
#   generic JSON body ............ 1 (content type) + 1 (parsed) = 2
#   + API-style path ............. 4  -> likely
#   + error envelope / GraphQL ... 5+ -> confirmed
# A URL name or a JSON content type therefore never reaches `confirmed` on
# its own, and a plain JSON object stays `uncertain`.
CONFIRMED_SCORE = 5
LIKELY_SCORE = 3

API_BEHAVIOR_LABELS = ("confirmed", "likely", "uncertain", "unlikely")
ACCESS_LABELS = (
    "public", "authentication_required", "forbidden", "unknown",
)


def _is_binary_content(ct: str | None) -> bool:
    """True for binary/static asset media types."""
    if not ct:
        return False
    if ct.startswith(("image/", "audio/", "video/", "font/")):
        return True
    return ct in _BINARY_TYPES or ct.startswith(
        "application/vnd.openxmlformats"
    )


def _is_json_content(ct: str | None) -> bool:
    """JSON content type: application/json or any *+json media type."""
    if not ct:
        return False
    return ct == "application/json" or ct.endswith("+json")


def _is_xml_content(ct: str | None) -> bool:
    if not ct:
        return False
    return ct in {"application/xml", "text/xml"} or ct.endswith("+xml")


def _is_text_content(ct: str | None) -> bool:
    if not ct:
        return False
    return ct.startswith("text/") or ct in _TEXTUAL_TYPES


def _is_private_host(host: str) -> bool:
    """True for loopback / private / link-local / reserved addresses.

    Local and lab targets are legitimate for this tool, so this is reported
    as context rather than used to block the request. Note the limitation:
    it only understands IP literals, so a hostname that resolves to a
    private address is reported as public. Upgrade path if that ever
    matters: resolve with getaddrinfo, and pin the connection to the
    resolved address so a second lookup cannot swap it.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified
    )


class EndpointAnalyzer:
    """Analyze discovery candidates with safe, bounded, read-only requests.

    The analyzer never raises from a public analysis method: failures are
    reported inside the result record so a batch always completes.
    """

    def __init__(
        self,
        timeout: float = 10,
        base_url: str | None = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        request_delay: float = 0.1,
        redact_sensitive: bool = False,
        send_sensitive_params: bool = False,
        probe_options: bool = True,
        probe_options_always: bool = False,
        allowed_hosts: tuple[str, ...] | list[str] | None = None,
        allowed_redirect_hosts: (
            tuple[str, ...] | list[str] | None
        ) = None,
    ) -> None:
        # Strict validation so configuration errors surface immediately
        # rather than as a confusing TypeError mid-batch.
        if type(timeout) not in (int, float) or isinstance(timeout, bool):
            raise ValueError("timeout must be a number > 0")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")

        if type(max_redirects) is not int or isinstance(
            max_redirects, bool
        ):
            raise ValueError("max_redirects must be an integer >= 0")
        if max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")

        if type(max_response_size) not in (int, float) or isinstance(
            max_response_size, bool
        ):
            raise ValueError("max_response_size must be a number > 0")
        if max_response_size <= 0:
            raise ValueError("max_response_size must be > 0")

        if type(request_delay) not in (int, float) or isinstance(
            request_delay, bool
        ):
            raise ValueError("request_delay must be a number >= 0")
        if request_delay < 0:
            raise ValueError("request_delay must be >= 0")

        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.follow_redirects = bool(follow_redirects)
        self.max_redirects = int(max_redirects)
        self.max_response_size = int(max_response_size)
        self.request_delay = float(request_delay)

        # Display vs transmission. Intentionally independent: redacting a
        # report must never change what is sent, and sending a parameter
        # must never change what the report shows.
        self.redact_sensitive = bool(redact_sensitive)
        self.send_sensitive_params = bool(send_sensitive_params)

        self.probe_options = bool(probe_options)
        self.probe_options_always = bool(probe_options_always)

        self.allowed_hosts = self._normalize_host_list(allowed_hosts)
        self.allowed_redirect_hosts = self._normalize_host_list(
            allowed_redirect_hosts
        )

        self.base_url: str | None = None
        if base_url is not None:
            if self._parse_http_url(str(base_url)) is None:
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
        self._wrapper_target: str | None = None

    # -- configuration helpers ----------------------------------------------

    @staticmethod
    def _normalize_host_list(
        hosts: tuple[str, ...] | list[str] | None,
    ) -> frozenset[str] | None:
        """Lowercase host allowlist, or None when unrestricted."""
        if hosts is None:
            return None
        out = {
            str(h).strip().lower()
            for h in hosts
            if str(h).strip()
        }
        return frozenset(out) or None

    def _host_permitted(
        self,
        host: str,
        allowlist: frozenset[str] | None,
    ) -> bool:
        """Allowlist check. None means unrestricted (lab targets allowed)."""
        if allowlist is None:
            return True
        return host.lower() in allowlist

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP session."""
        try:
            self._session.cookies.clear()
        except Exception:
            pass
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "EndpointAnalyzer":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- public analysis API -------------------------------------------------

    def analyze_endpoint(self, candidate: Any) -> dict[str, Any]:
        """Analyze one candidate; never raises, always returns a record."""
        result = self._new_result()
        try:
            self._analyze_into(result, candidate)
        except Exception as exc:
            logger.debug(
                "unexpected error while analyzing endpoint",
                exc_info=True,
            )
            result["error"] = {
                "type": "unexpected_error",
                "message": f"{type(exc).__name__}: {self._short(str(exc))}",
            }
        return result

    def analyze_candidates(self, candidates: Any) -> list[dict[str, Any]]:
        """Analyze many candidates.

        Accepts the discovery wrapper dict, a bare list, a single candidate,
        or None. Input order is preserved and duplicates are NOT removed:
        a candidate appearing twice yields two results, so the caller's
        discovery record stays auditable.
        """
        # Never leak a previous wrapper target into a later call.
        self._wrapper_target = None
        items: list[Any]

        if candidates is None:
            items = []
        elif isinstance(candidates, list):
            items = candidates
        elif isinstance(candidates, dict):
            inner = candidates.get("endpoints")
            if isinstance(inner, list):
                target = candidates.get("target")
                if isinstance(target, str) and target.strip():
                    self._wrapper_target = target.strip()
                items = inner
            else:
                items = [candidates]
        else:
            items = [candidates]

        try:
            return [self.analyze_endpoint(item) for item in items]
        finally:
            self._wrapper_target = None

    def analyze_discovery_file(
        self,
        input_path: str,
        output_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load discovery JSON, analyze it, optionally write results.

        Only the `endpoints` list is analyzed. `endpoint_count`,
        `pages_crawled` and `scanned_at` are ignored; `target` is used as
        the fallback base URL for relative candidates.
        """
        with open(input_path, encoding="utf-8") as fh:
            raw = fh.read()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON in {input_path}: {exc}"
            ) from exc

        if isinstance(data, dict) and not isinstance(
            data.get("endpoints"), list
        ):
            raise ValueError(
                "discovery JSON must contain an 'endpoints' list"
            )
        if not isinstance(data, (dict, list)):
            raise ValueError(
                "discovery JSON must be an object or a list"
            )

        results = self.analyze_candidates(data)

        if output_path is not None:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(
                    results, fh, indent=2, ensure_ascii=False,
                    default=str,
                )

        return results

    # -- core per-candidate flow --------------------------------------------

    def _analyze_into(
        self,
        result: dict[str, Any],
        candidate: Any,
    ) -> None:
        url_raw: Any = None
        source = SOURCE_DEFAULT
        found_in: list[str] | None = None
        requested_method: str | None = None

        if isinstance(candidate, str):
            url_raw = candidate
        elif isinstance(candidate, dict):
            url_raw = candidate.get("url")
            src = candidate.get("source")
            if isinstance(src, str) and src.strip():
                source = src.strip()
            fi = candidate.get("found_in")
            if isinstance(fi, list):
                strings = [e for e in fi if isinstance(e, str)]
                if strings:
                    # Provenance only. These URLs are reported, never requested.
                    found_in = [
                        self._truncate(s, FOUND_IN_TRUNCATE)
                        for s in strings[:MAX_FOUND_IN]
                    ]
            if isinstance(candidate.get("sources"), list):
                srcs = [
                    s for s in candidate["sources"]
                    if isinstance(s, str)
                ]
                if srcs and found_in is None:
                    found_in = [
                        self._truncate(s, FOUND_IN_TRUNCATE)
                        for s in srcs[:MAX_FOUND_IN]
                    ]
            meth = candidate.get("method")
            if isinstance(meth, str) and meth.strip():
                requested_method = meth.strip().upper()

        result["source"] = source
        result["found_in"] = found_in
        # Discovery's `method` is a hint (often "UNKNOWN"); the method that
        # was actually used is recorded in result["method"] after the GET.
        result["requested_method"] = requested_method

        if not isinstance(url_raw, str) or not url_raw.strip():
            result["error"] = {
                "type": "invalid_url",
                "message": "candidate has no usable URL string",
            }
            return

        cleaned = self._normalize_url_text(url_raw)
        if "&amp;" in cleaned.lower():
            cleaned = html.unescape(cleaned)
            result["warnings"].append(
                "url contained HTML-escaped '&amp;'; decoded "
                "before analysis"
            )

        base = self.base_url or self._wrapper_target

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
                "message": (
                    "candidate is not an absolute or relative URL"
                ),
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

        visible_url = self._rebuild(resolved)

        # Display form: the *resolved* URL, fragment removed, so the report
        # and the request agree. Redacted only if the caller asked for it.
        result["url"] = self._display_url(visible_url)

        # Query parameters come from the visible URL, before any
        # transmission sanitization, so the report reflects what discovery saw.
        result["parameters"] = self._extract_parameters(visible_url)
        result["url_context"] = self._describe_url_context(
            visible_url
        )

        request_url, changed = self._sanitize_query(visible_url)
        if changed:
            result["warnings"].append(
                "sensitive query parameter values were not sent "
                "(send_sensitive_params=False)"
            )

        net = self._perform_request(result, request_url)
        if net is None:
            return

        result["response_time_ms"] = round(
            net["elapsed_s"] * 1000, 1
        )
        self._finalize(result, net, request_url)

    # -- URL handling --------------------------------------------------------

    @staticmethod
    def _normalize_url_text(url: str) -> str:
        """Trim surrounding whitespace and bidirectional/BOM marks."""
        return url.strip().strip("‎‏﻿")

    @staticmethod
    def _parse_http_url(
        url: str,
    ) -> tuple[str, str, str, str, str] | None:
        """Split an http(s) URL, or None when it is not usable."""
        try:
            parts = urlsplit(url.strip())
        except (ValueError, UnicodeError):
            return None

        if parts.scheme.lower() not in ("http", "https"):
            return None

        try:
            _ = parts.port
        except ValueError:
            return None

        if not parts.hostname:
            return None

        # Reject userinfo (https://user:pass@host) so credentials are
        # never transmitted or echoed.
        if parts.username is not None or parts.password is not None:
            return None

        return (
            parts.scheme.lower(),
            parts.netloc,
            parts.path,
            parts.query,
            "",
        )

    def _resolve_url(
        self,
        url: str,
        base: str | None,
    ) -> tuple[str, str, str, str, str] | None:
        """Resolve a possibly-relative candidate URL against a base."""
        candidate = url
        if base and not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", url
        ):
            try:
                candidate = urljoin(base, url)
            except (ValueError, UnicodeError):
                return None

        try:
            parts = urlsplit(candidate)
            _ = parts.port
        except (ValueError, UnicodeError):
            return None

        scheme = parts.scheme.lower()

        if not parts.scheme and not parts.netloc:
            return None

        # An unsupported scheme with no host cannot be validated further;
        # hand it to the validator so the error message is specific.
        if scheme not in ("http", "https") and not parts.netloc:
            return (scheme, "", parts.path, parts.query, "")

        return (
            scheme,
            parts.netloc,
            parts.path,
            parts.query,
            "",
        )

    def _validate_resolved(
        self,
        parts: tuple[str, str, str, str, str],
    ) -> dict[str, str] | None:
        """Reject unsupported schemes, bad ports, and disallowed hosts."""
        try:
            split = urlsplit(urlunsplit(parts))
            scheme = split.scheme.lower()
            host = (split.hostname or "").lower()
            userinfo = (
                split.username is not None
                or split.password is not None
            )
            _ = split.port  # raises on a malformed port
        except (ValueError, UnicodeError):
            return {
                "type": "invalid_url",
                "message": "URL could not be parsed safely",
            }

        if scheme not in ("http", "https"):
            return {
                "type": "unsupported_scheme",
                "message": (
                    f"URL scheme '{scheme or 'none'}' is not supported "
                    "(http/https only)"
                ),
            }

        if not host:
            return {
                "type": "invalid_url",
                "message": "URL has no hostname",
            }

        if userinfo:
            return {
                "type": "invalid_url",
                "message": "URL contains userinfo which is rejected",
            }

        if not self._host_permitted(host, self.allowed_hosts):
            return {
                "type": "host_not_allowed",
                "message": (
                    f"host '{host}' is not in the configured "
                    "host allowlist"
                ),
            }

        return None

    @staticmethod
    def _rebuild(parts: tuple[str, str, str, str, str]) -> str:
        scheme, netloc, path, query, _frag = parts
        return urlunsplit((scheme, netloc, path, query, ""))

    def _describe_url_context(self, url: str) -> dict[str, Any]:
        """Passive context about the URL: scheme, host class, redirect path."""
        try:
            split = urlsplit(url)
            host = (split.hostname or "").lower()
            scheme = split.scheme.lower()
            port = split.port
        except (ValueError, UnicodeError):
            return {}

        return {
            "scheme": scheme or None,
            "host": host or None,
            "port": port,
            "is_private_host": _is_private_host(host) if host else False,
            "api_style_path": bool(
                _API_PATH_RE.search(split.path or "")
            ),
            "looks_like_login_path": bool(
                LOGIN_PATH_RE.search(split.path or "")
            ),
        }

    # -- sensitive data ------------------------------------------------------

    def _is_sensitive_key(self, key: str) -> bool:
        """True when a parameter/field NAME indicates sensitive data."""
        try:
            decoded = unquote(key)
        except Exception:
            decoded = key

        # Tokenize on separators and camelCase humps so "author" does not
        # match "auth" while "api_key"/"authToken"/"password" do.
        try:
            tokens = _KEY_TOKENS_RE.findall(decoded)
        except (TypeError, re.error):
            tokens = []

        if not tokens:
            norm = decoded.lower().replace("-", "").replace("_", "")
            return any(p in norm for p in SENSITIVE_PATTERNS)

        for tok in tokens:
            low = tok.lower()
            if low in SENSITIVE_PATTERNS or low in _SENSITIVE_COMPOUNDS:
                return True
            if low.endswith("s") and low[:-1] in SENSITIVE_PATTERNS:
                return True  # plurals: tokens, keys, secrets, cookies
        return False

    def _apply_redaction(self, value: str) -> str:
        """Redact a value only when redaction is enabled."""
        if not self.redact_sensitive:
            return value
        return REDACTED

    def _display_url(self, url: str) -> str:
        """URL as shown in the report (redacted per configuration)."""
        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return url

        if not parts.query:
            return url

        out: list[str] = []
        for pair in parts.query.split("&"):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            if self._is_sensitive_key(name) and value:
                out.append(f"{name}={self._apply_redaction(value)}")
            else:
                out.append(pair)

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                "&".join(out),
                parts.fragment,
            )
        )

    def _sanitize_query(self, url: str) -> tuple[str, bool]:
        """Blank sensitive query values unless sending them is authorized.

        Display is unaffected: this only governs the request line.
        """
        if self.send_sensitive_params:
            return url, False

        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return url, False

        if not parts.query:
            return url, False

        pairs = parse_qsl(parts.query, keep_blank_values=True)
        changed = False
        out: list[str] = []

        for name, value in pairs:
            encoded_name = quote(name, safe="")
            if self._is_sensitive_key(name) and value:
                out.append(f"{encoded_name}=")
                changed = True
            else:
                out.append(f"{encoded_name}={quote(value, safe='')}")

        rebuilt = urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                "&".join(out),
                "",
            )
        )
        return rebuilt, changed

    def _scan_secret_values(
        self,
        text: str,
        location: str,
        findings: list[dict[str, Any]],
    ) -> None:
        """Record high-confidence secret formats found in a text blob."""
        if len(findings) >= MAX_SENSITIVE_FINDINGS:
            return
        chunk = text[:MAX_SECRET_SCAN_BYTES]
        seen: set[tuple[str, str]] = set()
        for label, pattern in _SECRET_FORMATS:
            if len(findings) >= MAX_SENSITIVE_FINDINGS:
                return
            for m in pattern.finditer(chunk):
                raw = m.group(0)
                if label in ("bearer_token", "basic_auth_header",
                             "credential_assignment"):
                    # Report the credential itself, not the whole header.
                    raw = m.group(1)
                value = self._truncate(
                    self._apply_redaction(raw), MAX_SENSITIVE_VALUE
                )
                key = (label, value)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "location": location,
                    "reason": f"matched {label} pattern",
                    "value": value,
                    "type": label,
                })
                if len(findings) >= MAX_SENSITIVE_FINDINGS:
                    return

    def _scan_json_sensitive(
        self,
        value: Any,
        findings: list[dict[str, Any]],
        path: str = "$",
        budget: list[int] | None = None,
    ) -> None:
        """Walk parsed JSON, flagging sensitive field names and secret values.

        Iterative rather than recursive so a deeply nested body cannot
        exhaust the interpreter stack. Bounded by MAX_JSON_WALK_NODES and
        MAX_SCHEMA_DEPTH so a huge body cannot make this unbounded.
        """
        if budget is None:
            budget = [MAX_JSON_WALK_NODES]

        stack: list[tuple[Any, str, int]] = [(value, path, 0)]
        while stack:
            if budget[0] <= 0 or len(findings) >= MAX_SENSITIVE_FINDINGS:
                return
            node, node_path, depth = stack.pop()
            budget[0] -= 1

            if isinstance(node, str):
                # Only reachable for a top-level scalar body: string leaves
                # inside containers are scanned in place and never pushed.
                if len(node) >= 16:
                    self._scan_secret_values(node, node_path, findings)
                continue

            if isinstance(node, dict):
                for key, child in node.items():
                    child_path = f"{node_path}.{key}"
                    # Scan string leaves in place: they are never pushed
                    # onto the walk stack, so a JWT sitting under a
                    # sensitive key would otherwise go unreported.
                    if isinstance(child, str) and len(child) >= 16:
                        self._scan_secret_values(
                            child, child_path, findings
                        )
                    if (
                        isinstance(key, str)
                        and self._is_sensitive_key(key)
                    ):
                        if isinstance(child, (dict, list)):
                            summary = (
                                f"<{type(child).__name__} with "
                                f"{len(child)} entries>"
                            )
                        else:
                            summary = self._display_value(child)
                        findings.append({
                            "location": child_path,
                            "reason": (
                                "field name indicates sensitive data"
                            ),
                            "value": self._truncate(
                                self._apply_redaction(summary),
                                MAX_SENSITIVE_VALUE,
                            ),
                            "type": "sensitive_field",
                        })
                    if depth < MAX_SCHEMA_DEPTH and isinstance(
                        child, (dict, list)
                    ):
                        stack.append((child, child_path, depth + 1))
            elif isinstance(node, list):
                for idx, child in enumerate(node[:MAX_KEYS_PER_OBJECT]):
                    if isinstance(child, (dict, list)):
                        stack.append(
                            (child, f"{node_path}[{idx}]", depth + 1)
                        )

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return value
        return f"<{type(value).__name__}>"

    def _truncate(self, text: str, limit: int) -> str:
        if not isinstance(text, str):
            text = str(text)
        return text if len(text) <= limit else text[:limit] + "…"

    @staticmethod
    def _short(message: str) -> str:
        message = (message or "").replace("\n", " ").strip()
        return message[:MAX_ERROR_MESSAGE] or "request failed"

    def _safe_log_url(self, url: str) -> str:
        try:
            p = urlsplit(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except (ValueError, UnicodeError):
            return "<unparseable-url>"

    # -- networking ----------------------------------------------------------

    def _throttle(self) -> None:
        """Enforce request_delay between network requests."""
        if self._last_request_end is None or self.request_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_end
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _mark_request_done(self) -> None:
        self._last_request_end = time.monotonic()

    def _set_network_error(
        self,
        result: dict[str, Any],
        error_type: str,
        message: str,
        chain: list[str],
    ) -> None:
        result["method"] = "GET"
        result["final_url"] = self._display_url(
            chain[-1] if chain else ""
        )
        result["redirect_chain"] = [
            self._display_url(u) for u in chain
        ]
        result["redirected"] = len(chain) > 1
        result["error"] = {
            "type": error_type,
            "message": self._short(message),
        }

    def _request_once(
        self,
        url: str,
        method: str = "GET",
    ) -> requests.Response:
        """Issue one read-only request with redirects disabled.

        Redirects are followed manually by the caller so every hop can be
        validated and recorded.
        """
        return self._session.request(
            method,
            url,
            allow_redirects=False,
            stream=True,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

    def _perform_request(
        self,
        result: dict[str, Any],
        initial_url: str,
    ) -> dict[str, Any] | None:
        """Manual-redirect GET loop with loop detection and host policy.

        Returns one observation dict, or None when the request never
        completed (the error is recorded on `result`).
        """
        current_url = initial_url
        chain: list[str] = [initial_url]
        seen_urls: set[str] = {self._canonical_for_loop_check(current_url)}
        origin = self._redirect_host(initial_url)
        hops = 0
        elapsed_s = 0.0
        redirect_details: list[dict[str, Any]] = []
        result["method"] = "GET"

        # Cookies may persist across hops of one endpoint but are always
        # cleared between endpoints, so nothing leaks across candidates.
        try:
            while True:
                self._throttle()
                logger.debug(
                    "requesting %s", self._safe_log_url(current_url)
                )
                t0 = time.perf_counter()
                try:
                    response = self._request_once(current_url)
                except Timeout as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "timeout", str(exc), chain
                    )
                    return None
                except SSLError as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "ssl_error", str(exc), chain
                    )
                    return None
                except (
                    InvalidURL, InvalidSchema, MissingSchema
                ) as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "invalid_url", str(exc), chain
                    )
                    return None
                except RequestsConnectionError as exc:
                    self._mark_request_done()
                    # DNS failure surfaces as a connection error subclass.
                    self._set_network_error(
                        result, "connection_error", str(exc), chain
                    )
                    return None
                except RequestException as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "request_error", str(exc), chain
                    )
                    return None
                except Exception as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result,
                        "unexpected_error",
                        f"{type(exc).__name__}: {exc}",
                        chain,
                    )
                    return None

                elapsed_s += time.perf_counter() - t0
                try:
                    status = response.status_code
                    headers = {
                        k.lower(): v
                        for k, v in response.headers.items()
                    }
                    content_type = self._normalize_content_type(
                        headers.get("content-type")
                    )
                    location = headers.get("location")

                    # One observation shape for every exit path; the body
                    # fields stay None until a body is actually read.
                    obs: dict[str, Any] = {
                        "headers": headers,
                        "content_type": content_type,
                        "body": None,
                        "size": None,
                        "truncated": False,
                        "deadline": False,
                        "status": status,
                        "final_url": current_url,
                        "chain": chain,
                        "blocked": False,
                        "too_many": False,
                        "location": location,
                        "elapsed_s": elapsed_s,
                        "redirect_details": redirect_details,
                    }

                    if (
                        status in REDIRECT_STATUSES
                        and location and location.strip()
                        and self.follow_redirects
                    ):
                        if hops >= self.max_redirects:
                            obs.update(self._read_body(
                                response, headers, content_type, result
                            ))
                            obs["too_many"] = True
                            return obs

                        nxt, blocked_reason = self._resolve_redirect(
                            current_url, location, origin
                        )
                        redirect_details.append({
                            "from": self._display_url(current_url),
                            "status": status,
                            "location": self._display_url(
                                location.strip()
                            ),
                            "followed": nxt is not None,
                        })

                        if nxt is None:
                            obs["blocked"] = True
                            obs["block_reason"] = (
                                blocked_reason
                                or "redirect target blocked"
                            )
                            obs["final_url"] = chain[-1]
                            return obs

                        loop_key = self._canonical_for_loop_check(nxt)
                        if loop_key in seen_urls:
                            result["warnings"].append(
                                f"redirect loop detected at "
                                f"{self._safe_log_url(nxt)}"
                            )
                            obs["blocked"] = True
                            obs["block_reason"] = "redirect loop detected"
                            obs["final_url"] = nxt
                            obs["chain"] = chain + [nxt]
                            return obs

                        try:
                            response.close()
                        except Exception:
                            pass

                        nxt_request, hop_changed = self._sanitize_query(
                            nxt
                        )
                        if hop_changed:
                            result["warnings"].append(
                                "sensitive query parameter values were "
                                "not sent on a redirect hop "
                                "(send_sensitive_params=False)"
                            )
                        seen_urls.add(loop_key)
                        current_url = nxt_request
                        chain.append(nxt_request)
                        hops += 1
                        continue

                    # Final response for this candidate.
                    t_body = time.perf_counter()
                    obs.update(self._read_body(
                        response, headers, content_type, result
                    ))
                    obs["elapsed_s"] += time.perf_counter() - t_body
                    if status in REDIRECT_STATUSES and not (
                        location and location.strip()
                    ):
                        result["warnings"].append(
                            "redirect response without Location header"
                        )
                    return obs
                finally:
                    try:
                        response.close()
                    except Exception:
                        pass
                    self._mark_request_done()
        finally:
            # Clear cookies exactly once per candidate.
            try:
                self._session.cookies.clear()
            except Exception:
                pass

    @staticmethod
    def _canonical_for_loop_check(url: str) -> str:
        """Fragment-free, order-insensitive key for loop detection."""
        try:
            parts = urlsplit(url)
            query = "&".join(
                sorted(p for p in parts.query.split("&") if p)
            )
            return urlunsplit(
                (
                    parts.scheme.lower(),
                    (parts.netloc or "").lower(),
                    parts.path or "/",
                    query,
                    "",
                )
            )
        except (ValueError, UnicodeError):
            return url

    def _redirect_host(
        self,
        url: str,
    ) -> tuple[str, str, int] | None:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            port = parts.port
        except (ValueError, UnicodeError):
            return None

        if not host:
            return None

        if port is None:
            port = 443 if parts.scheme.lower() == "https" else 80
        return (parts.scheme.lower(), host, port)

    def _resolve_redirect(
        self,
        current_url: str,
        location: str,
        origin: tuple[str, str, int] | None,
    ) -> tuple[str | None, str | None]:
        """Validate a redirect target. Cross-host hops are not followed."""
        try:
            target = urljoin(current_url, location.strip())
            parts = urlsplit(target)
            thost = (parts.hostname or "").lower()
            tport = parts.port
        except (ValueError, UnicodeError):
            return None, "redirect target could not be parsed"

        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return None, (
                "redirect target uses an unsupported scheme "
                f"'{scheme or 'none'}'"
            )

        if parts.username is not None or parts.password is not None:
            return None, "redirect target contains userinfo"

        if not thost:
            return None, "redirect target has no hostname"

        if tport is None:
            tport = 443 if scheme == "https" else 80

        origin_host = origin[1] if origin else None

        # Cross-host redirects are NOT followed unless an explicit
        # redirect-host allowlist names the target. With no allowlist
        # configured, same-host is the policy: a server must not be able
        # to bounce the probe to an arbitrary external host.
        if thost != origin_host:
            if (
                self.allowed_redirect_hosts is None
                or thost not in self.allowed_redirect_hosts
            ):
                return None, (
                    f"redirect target is on a different host "
                    f"('{thost}'); not followed"
                )

        if origin is not None:
            oscheme, ohost, oport = origin
            # HTTP -> HTTPS on the default port is the one benign
            # scheme/port change; everything else cross-host is refused.
            upgrade = (
                oscheme == "http" and scheme == "https"
                and oport == 80 and tport == 443
            )
            if thost == ohost and not upgrade:
                if scheme != oscheme:
                    return None, (
                        "redirect target changes the scheme on the "
                        "same host"
                    )
                if tport != oport:
                    return None, (
                        "redirect target changes the port on the "
                        "same host"
                    )

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                parts.query,
                "",
            )
        ), None

    def _probe_options(
        self,
        url: str,
    ) -> dict[str, Any] | None:
        """OPTIONS probe: allowed methods and CORS preflight shape.

        Read-only and bodyless, so it is safe. Returns None when the probe
        itself fails; the failure is never fatal to the endpoint result.
        """
        try:
            self._throttle()
            t0 = time.perf_counter()
            response = self._request_once(url, method="OPTIONS")
            try:
                elapsed = round(
                    (time.perf_counter() - t0) * 1000, 1
                )
                headers = {
                    k.lower(): v
                    for k, v in response.headers.items()
                }
                # Drain a bounded amount so the connection can be reused.
                try:
                    for chunk in response.iter_content(
                        chunk_size=CHUNK_SIZE
                    ):
                        if len(chunk) >= CHUNK_SIZE:
                            break
                except Exception:
                    pass
                allow = headers.get("allow") or ""
                methods = [
                    m.strip().upper()
                    for m in allow.split(",")
                    if m.strip()
                ]
                return {
                    "method": "OPTIONS",
                    "status": response.status_code,
                    "allow_header": allow or None,
                    "allowed_methods": methods or None,
                    "accepts_options": response.status_code
                    not in (400, 404, 405, 501),
                    "cors": {
                        "allow_origin": headers.get(
                            "access-control-allow-origin"
                        ),
                        "allow_methods": headers.get(
                            "access-control-allow-methods"
                        ),
                        "allow_headers": headers.get(
                            "access-control-allow-headers"
                        ),
                        "allow_credentials": headers.get(
                            "access-control-allow-credentials"
                        ),
                    },
                    "response_time_ms": elapsed,
                }
            finally:
                try:
                    response.close()
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("OPTIONS probe failed", exc_info=True)
            return {
                "method": "OPTIONS",
                "status": None,
                "error": {
                    "type": type(exc).__name__,
                    "message": self._short(str(exc)),
                },
            }
        finally:
            self._mark_request_done()

    # -- body reading --------------------------------------------------------

    def _read_body(
        self,
        response: requests.Response,
        headers: dict[str, str],
        content_type: str | None,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Read at most max_response_size raw bytes, with a decoded cap.

        The raw limit is applied before decoding; the decoded limit then
        bounds memory for pathological encodings. The complete body is
        never retained in the result.
        """
        raw_size = 0
        truncated = False
        deadline_exceeded = False
        chunks: list[str] = []
        collected_chars = 0
        deadline = time.monotonic() + self.timeout
        charset = self._charset_from_headers(headers)

        try:
            for raw in response.iter_content(chunk_size=CHUNK_SIZE):
                if not raw:
                    continue
                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break

                remaining = self.max_response_size - raw_size
                if remaining <= 0:
                    truncated = True
                    break

                if len(raw) > remaining:
                    raw = raw[:remaining]
                    truncated = True

                raw_size += len(raw)

                if collected_chars < BODY_READ_LIMIT:
                    piece = self._decode(raw, charset)
                    remaining_chars = (
                        BODY_READ_LIMIT - collected_chars
                    )
                    if len(piece) > remaining_chars:
                        piece = piece[:remaining_chars]
                    chunks.append(piece)
                    collected_chars += len(piece)

                if truncated:
                    break

                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break
        except Exception as exc:
            result["warnings"].append(
                f"body read interrupted: {type(exc).__name__}: "
                f"{self._short(str(exc))}"
            )

        if truncated:
            result["warnings"].append(
                f"body truncated at {self.max_response_size} bytes; "
                "structure inference may be incomplete"
            )
        if deadline_exceeded:
            result["warnings"].append(
                "body read deadline exceeded"
            )

        return {
            "body": "".join(chunks),
            "size": raw_size,
            "truncated": truncated,
            "deadline": deadline_exceeded,
        }

    @staticmethod
    def _charset_from_headers(headers: dict[str, str]) -> str | None:
        raw = headers.get("content-type") or ""
        m = re.search(r"charset\s*=\s*\"?([\w\-]+)", raw, re.I)
        return m.group(1).lower() if m else None

    @staticmethod
    def _decode(raw: bytes, charset: str | None) -> str:
        """Decode with the declared charset, tolerating bad bytes."""
        for encoding in (charset, "utf-8-sig", "utf-8", "latin-1"):
            if not encoding:
                continue
            try:
                return raw.decode(encoding, errors="replace")
            except (LookupError, UnicodeError):
                continue
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _normalize_content_type(value: str | None) -> str | None:
        if value is None:
            return None
        ct = value.strip().lower()
        if not ct:
            return None
        return ct.split(";", 1)[0].strip() or None

    def _extract_headers(
        self,
        headers: dict[str, str],
    ) -> dict[str, str | None]:
        """Capture a curated header set; never dump everything."""
        out: dict[str, str | None] = {}
        for key in _CAPTURED_HEADERS:
            value = headers.get(key)
            if value is None:
                out[key] = None
                continue
            value = value.strip()
            if key == "location":
                value = self._display_url(value)
            elif self.redact_sensitive and key in _SENSITIVE_HEADERS:
                value = REDACTED
            out[key] = self._truncate(value, MAX_HEADER_VALUE)
        return out

    # -- parameters ----------------------------------------------------------

    def _extract_parameters(
        self,
        url: str,
    ) -> list[dict[str, Any]]:
        """Visible query parameters with sensitivity flagged."""
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

            sensitive = self._is_sensitive_key(name)
            params.append({
                "name": name,
                "location": "query",
                # Shown by default; redacted only when configured.
                "example_value": self._truncate(
                    self._apply_redaction(value) if sensitive else value,
                    MAX_PARAM_EXAMPLE,
                ),
                "sensitive": sensitive,
                "value_length": len(value),
            })

        return params

    def _path_parameters(self, url: str) -> list[dict[str, Any]]:
        """Detect obvious identifier segments (numeric, UUID, ObjectId)."""
        try:
            path = urlsplit(url).path
            segments = [s for s in path.split("/") if s]
        except (ValueError, UnicodeError, AttributeError):
            return []

        out: list[dict[str, Any]] = []
        for idx, seg in enumerate(segments):
            if NUMERIC_SEG_RE.fullmatch(seg):
                kind = "numeric_id"
            elif UUID_SEG_RE.fullmatch(seg):
                kind = "uuid"
            elif OBJECTID_SEG_RE.fullmatch(seg):
                kind = "object_id"
            elif HEX_SEG_RE.fullmatch(seg):
                kind = "hex_identifier"
            else:
                continue

            out.append({
                "name": None,
                "location": "path",
                "segment": self._truncate(seg, MAX_PARAM_EXAMPLE),
                "position": idx,
                "parameter_type": kind,
            })
        return out

    # -- response structure --------------------------------------------------

    @staticmethod
    def _looks_like_html(body: str) -> bool:
        head = body.lstrip()[:200].lower()
        return (
            head.startswith("<!doctype html")
            or head.startswith("<html")
        )

    @staticmethod
    def _try_parse_json(text: str) -> tuple[bool, Any]:
        try:
            return True, json.loads(text)
        except (RecursionError, ValueError, TypeError):
            return False, None

    def _detect_structure(
        self,
        body: str,
        content_type: str | None,
        net: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """FIRST MATCH WINS response-structure detection."""
        if body is None:
            return None

        stripped = body.strip()

        if not stripped:
            if _is_json_content(content_type):
                result["warnings"].append("empty JSON body")
            return {"type": "empty"}

        if _is_binary_content(content_type):
            return {"type": "binary"}

        json_ct = _is_json_content(content_type)
        starts_json = stripped[0] in "{["
        incomplete = bool(net.get("truncated") or net.get("deadline"))

        if json_ct or starts_json:
            ok, parsed = self._try_parse_json(stripped)
            if ok:
                if not json_ct and isinstance(parsed, (dict, list)):
                    result["warnings"].append(
                        f"JSON body despite content type "
                        f"{content_type or 'unknown'}"
                    )
                return self._infer_structure(parsed, 1)
            # A truncated body is NOT definitively malformed: the missing
            # bytes may simply have been cut by the size/deadline limit.
            if incomplete:
                result["warnings"].append(
                    "body was incomplete; JSON could not be parsed "
                    "and the response is inconclusive rather than "
                    "malformed"
                )
                return {
                    "type": "unknown",
                    "reason": "incomplete_body",
                }
            if json_ct:
                if self._looks_like_html(stripped):
                    if _is_xml_content(content_type):
                        return {"type": "xml"}
                    return {"type": "html"}
                result["warnings"].append("malformed JSON")
                return {"type": "unknown", "reason": "malformed_json"}

        if (
            _is_xml_content(content_type)
            or stripped.lower().startswith("<?xml")
            or (
                stripped[:1] == "<"
                and self._looks_like_xml(stripped)
            )
        ):
            if incomplete:
                return {"type": "unknown", "reason": "incomplete_body"}
            if not self._looks_like_html(stripped):
                struct = self._parse_xml_structure(stripped)
                if struct is not None:
                    if (
                        not _is_xml_content(content_type)
                        and not stripped.lower().startswith("<?xml")
                    ):
                        result["warnings"].append(
                            f"XML body despite content type "
                            f"{content_type or 'unknown'}"
                        )
                    return struct
            if _is_xml_content(content_type):
                result["warnings"].append("malformed XML")
                return {"type": "unknown", "reason": "malformed_xml"}

        if content_type == "text/html" or self._looks_like_html(stripped):
            return {"type": "html"}

        if _is_text_content(content_type) or content_type in _JS_CSS_TYPES:
            return {"type": "text"}

        return {"type": "unknown", "reason": "no_format_match"}

    @staticmethod
    def _looks_like_xml(stripped: str) -> bool:
        head = stripped[:200].lower()
        return head.startswith("<") and re.match(
            r"<\??[a-z_][\w\-.]*[:\s/>?]", head
        ) is not None

    @staticmethod
    def _strip_ns(tag: str) -> tuple[str, str | None]:
        if tag.startswith("{"):
            ns, _, local = tag[1:].partition("}")
            return local, ns or None
        return tag, None

    def _parse_xml_structure(self, stripped: str) -> dict[str, Any] | None:
        """Parse an XML body into a compact structure.

        Uses stdlib ElementTree only. ElementTree does not resolve external
        entities and raises on undefined ones, so XXE and entity-expansion
        payloads fail to parse rather than being interpreted.
        """
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError:
            return None
        except (ValueError, MemoryError, RecursionError):
            return None

        local, _ns = self._strip_ns(root.tag)
        struct: dict[str, Any] = self._infer_xml_element(root, 1)

        children = struct.get("children") or {}
        low = local.lower()
        if low == "rss" or (low == "feed" and "entry" in children):
            struct["feed"] = "rss" if low == "rss" else "atom"
        elif low == "feed" and "item" in children:
            struct["feed"] = "rss"

        if low == "envelope":
            body_child = None
            fault = False
            nested = struct.get("nested") or {}
            for child in children:
                if child.lower() == "body":
                    ops = list((nested.get(child) or {}).get("children") or {})
                    if ops:
                        body_child = ops[0]
                        op_nested = nested.get(ops[0]) or {}
                        fault = "fault" in (
                            op_nested.get("children") or {}
                        ) or ops[0].lower() == "fault"
                    break
            struct["soap"] = True
            if body_child:
                struct["operation"] = body_child
            if fault:
                struct["fault"] = True

        return struct

    def _infer_xml_element(
        self,
        elem: Any,
        depth: int,
    ) -> dict[str, Any]:
        children: dict[str, int] = {}
        for child in elem:
            try:
                name, _ = self._strip_ns(child.tag)
            except (ValueError, AttributeError):
                continue
            children[name] = children.get(name, 0) + 1

        struct: dict[str, Any] = {
            "type": "element",
            "root": self._strip_ns(elem.tag)[0],
        }
        if children:
            struct["children"] = {
                n: children[n] for n in list(children)[:MAX_KEYS_PER_OBJECT]
            }
            repeated = sorted(
                n for n, c in children.items() if c > 1
            )
            if repeated:
                struct["repeated"] = repeated[:MAX_KEYS_PER_OBJECT]
            if depth < MAX_SCHEMA_DEPTH:
                nested: dict[str, Any] = {}
                seen: set[str] = set()
                for child in list(elem):
                    try:
                        name, _ = self._strip_ns(child.tag)
                    except (ValueError, AttributeError):
                        continue
                    if name in seen or len(nested) >= MAX_KEYS_PER_OBJECT:
                        continue
                    seen.add(name)
                    nested[name] = self._infer_xml_element(
                        child, depth + 1
                    )
                if nested:
                    struct["nested"] = nested
        else:
            text = (elem.text or "").strip()
            if text:
                struct["text"] = text[:MAX_PARAM_EXAMPLE]
        return struct

    def _primitive_type(self, value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        return "unknown"

    def _infer_structure(
        self,
        value: Any,
        depth: int = 1,
    ) -> dict[str, Any]:
        """Infer a compact JSON structure down to MAX_SCHEMA_DEPTH."""
        if isinstance(value, dict):
            keys = list(value.keys())
            struct: dict[str, Any] = {
                "type": "object",
                "keys": [str(k) for k in keys[:MAX_KEYS_PER_OBJECT]],
            }
            if len(keys) > MAX_KEYS_PER_OBJECT:
                struct["note"] = (
                    f"only first {MAX_KEYS_PER_OBJECT} keys recorded"
                )

            if depth < MAX_SCHEMA_DEPTH:
                nested: dict[str, Any] = {}
                for key in keys[:MAX_KEYS_PER_OBJECT]:
                    child = value[key]
                    if isinstance(child, (dict, list)):
                        nested[str(key)] = self._infer_structure(
                            child, depth + 1
                        )
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
                                obj_keys.append(str(key))
                if obj_keys:
                    struct["item_keys"] = obj_keys[
                        :MAX_KEYS_PER_OBJECT
                    ]
            return struct

        return {"type": self._primitive_type(value)}

    def _analyze_json_traits(
        self,
        parsed: Any,
    ) -> dict[str, Any]:
        """Detect pagination fields and data-envelope wrappers."""
        traits: dict[str, Any] = {
            "pagination_detected": False,
            "pagination_fields": [],
            "data_wrappers": [],
        }
        if not isinstance(parsed, dict):
            return traits

        lowered = {str(k).lower(): k for k in parsed.keys()}

        traits["pagination_fields"] = [
            str(lowered[k])
            for k in sorted(lowered)
            if k in _PAGINATION_KEYS
        ]
        traits["pagination_detected"] = bool(
            traits["pagination_fields"]
        )
        traits["data_wrappers"] = [
            str(lowered[k])
            for k in sorted(lowered)
            if k in _DATA_WRAPPER_KEYS
        ]

        # Report a few concrete pagination values as observations.
        observed: dict[str, Any] = {}
        for field in traits["pagination_fields"][:6]:
            val = parsed.get(field)
            if isinstance(val, (int, float, bool)) or (
                isinstance(val, str) and len(val) <= 60
            ):
                observed[field] = val
        if observed:
            traits["pagination_values"] = observed
        return traits

    # -- post-response finalization ------------------------------------------

    @staticmethod
    def _status_category(status: int) -> str:
        if 100 <= status < 200:
            return "informational"
        if 200 <= status < 300:
            return "success"
        if 300 <= status < 400:
            return "redirect"
        if 400 <= status < 500:
            return "client_error"
        if 500 <= status < 600:
            return "server_error"
        return "unknown"

    def _finalize(
        self,
        result: dict[str, Any],
        net: dict[str, Any],
        initial_url: str,
    ) -> None:
        headers: dict[str, str] = net["headers"]
        content_type: str | None = net["content_type"]
        status: int = net["status"]
        body: str | None = net["body"]
        chain: list[str] = net["chain"]
        final_url: str = net["final_url"]

        result["status"] = status
        result["status_category"] = self._status_category(status)
        result["content_type"] = content_type
        result["response_size"] = net["size"]
        result["response_size_truncated"] = bool(net["truncated"])
        result["redirected"] = len(chain) > 1
        result["redirect_chain"] = [
            self._display_url(u) for u in chain
        ]
        result["redirect_details"] = net.get("redirect_details") or []
        result["final_url"] = self._display_url(final_url)
        result["headers"] = self._extract_headers(headers)

        # Path identifiers come from the URL that was actually requested.
        result["parameters"].extend(
            self._path_parameters(final_url)
        )

        struct = None
        parsed_json: Any = None
        json_ok = False
        if body is not None:
            struct = self._detect_structure(
                body, content_type, net, result
            )
            if isinstance(struct, dict) and struct.get("type") in (
                "object", "array"
            ):
                json_ok = True
                ok, parsed_json = self._try_parse_json(body.strip())
                if ok:
                    result["json_analysis"] = self._analyze_json_traits(
                        parsed_json
                    )

        result["response_structure"] = struct

        if content_type is None:
            result["warnings"].append("missing Content-Type header")

        # OPTIONS probe: most useful exactly when GET was rejected with 405.
        if self.probe_options:
            should_probe = self.probe_options_always or status in (
                405, 501
            ) or (
                status in (401, 403) and not headers.get("allow")
            )
            if should_probe:
                result["options"] = self._probe_options(final_url)

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
            "options": result.get("options"),
            "json_ok": json_ok,
        }

        result["api_behavior"] = self._classify_api_behavior(ctx)
        result["access"] = self._classify_access(ctx)

        # Sensitive findings are collected first so the security posture can
        # account for a response that actually exposed secrets (e.g. a token
        # in the body), not just sensitive query parameters.
        result["sensitive_findings"] = self._collect_sensitive(
            result, net, body, parsed_json, json_ok
        )
        result["security_posture"] = self._security_posture(
            ctx, result
        )

        if net.get("blocked"):
            result["error"] = {
                "type": "blocked_redirect",
                "message": net.get(
                    "block_reason", "redirect target blocked"
                ),
            }
        elif net.get("too_many"):
            result["error"] = {
                "type": "too_many_redirects",
                "message": (
                    f"more than {self.max_redirects} redirects "
                    "encountered"
                ),
            }

    # -- sensitive collection ------------------------------------------------

    def _collect_sensitive(
        self,
        result: dict[str, Any],
        net: dict[str, Any],
        body: str | None,
        parsed_json: Any,
        json_ok: bool,
    ) -> list[dict[str, Any]]:
        """Gather sensitive findings across URL, headers, and body."""
        findings: list[dict[str, Any]] = []

        # 1. Query parameter names.
        for param in result.get("parameters") or []:
            if not param.get("sensitive"):
                continue
            if param.get("location") != "query":
                continue
            findings.append({
                "location": f"query.{param.get('name')}",
                "reason": "query parameter name indicates sensitive data",
                "value": param.get("example_value"),
                "type": "sensitive_parameter",
            })

        # 2. Sensitive header names, and secret formats in header values.
        headers: dict[str, str] = net["headers"]
        for name in sorted(_SENSITIVE_HEADER_NAMES):
            if name not in headers:
                continue
            findings.append({
                "location": f"header.{name}",
                "reason": "response header carries credential material",
                "value": self._truncate(
                    self._apply_redaction(headers[name]),
                    MAX_SENSITIVE_VALUE,
                ),
                "type": "sensitive_header",
            })
        self._scan_secret_values(
            "\n".join(
                f"{k}: {v}" for k, v in headers.items()
                if k not in _SENSITIVE_HEADERS
            ),
            "headers",
            findings,
        )

        # 3. JSON body: sensitive field names plus secret formats.
        if json_ok and parsed_json is not None:
            self._scan_json_sensitive(parsed_json, findings)
        elif body:
            self._scan_secret_values(body, "body", findings)

        if len(findings) > MAX_SENSITIVE_FINDINGS:
            result["warnings"].append(
                f"sensitive findings truncated at "
                f"{MAX_SENSITIVE_FINDINGS} entries"
            )
            findings = findings[:MAX_SENSITIVE_FINDINGS]

        return findings

    # -- classification ------------------------------------------------------

    def _parsed_container(
        self,
        struct: dict[str, Any] | None,
    ) -> bool:
        return (
            isinstance(struct, dict)
            and struct.get("type") in ("object", "array")
        )

    def _api_path_signal(self, ctx: dict[str, Any]) -> str | None:
        """Return the matched API-ish path segment, if any.

        The final URL is preferred, but a redirect onto a login page must not
        erase the original API path, so the requested URL is the fallback.
        A path name is weak evidence on its own and is never sufficient for
        `confirmed`.
        """
        for key in ("final_url", "initial_url"):
            try:
                path = urlsplit(ctx.get(key) or "").path
            except (ValueError, UnicodeError):
                continue
            if not path:
                continue
            m = _API_PATH_RE.search(path)
            if m:
                return m.group(0)
        return None

    def _json_error_envelope(
        self,
        ctx: dict[str, Any],
        top_keys: list[str],
    ) -> tuple[list[str], bool]:
        """Describe a machine-readable API error envelope, if the body is one.

        Returns (evidence lines, is_strong). Keys like `statusCode` /
        `errorCode` stand alone. Common keys (`error`, `message`, ...) only
        count on a 4xx/5xx status, and 404/410 is discounted entirely unless
        an API-specific key is present, because a generic miss handler is
        not an API error contract.
        """
        if not top_keys:
            return [], False

        lowered = [k.lower() for k in top_keys]
        strong = [k for k in lowered if k in _ERROR_KEYS_STRONG]
        supporting = [
            k for k in lowered if k in _ERROR_KEYS_SUPPORTING
        ]
        status = ctx["status"]
        is_error_status = status in _API_ERROR_STATUSES
        is_generic_miss = status in _GENERIC_MISS_STATUSES

        # Exactly ONE line is emitted for the envelope so evidence numbers
        # stay unique and citable; the sub-cases are folded into it.
        hits: list[str] = []
        if strong:
            detail = ", ".join(sorted(strong)[:4])
            if not is_error_status:
                hits.append(
                    "9: API-style error/status fields present in a "
                    f"{status} response: {detail}"
                )
            else:
                extra = ""
                if supporting and not is_generic_miss:
                    extra = "; also " + ", ".join(sorted(supporting)[:4])
                hits.append(f"9: API error envelope keys: {detail}{extra}")
        elif supporting and is_error_status:
            detail = ", ".join(sorted(supporting)[:4])
            if is_generic_miss:
                hits.append(
                    f"9: generic {status} body with only common "
                    f"error keys ({detail}); not treated as an API "
                    "error envelope"
                )
            else:
                hits.append(
                    f"9: error keys on HTTP {status}: {detail}"
                )

        is_strong_envelope = bool(
            strong
            or (supporting and is_error_status and not is_generic_miss)
        )
        return hits, is_strong_envelope

    def _top_level_keys(
        self,
        struct: dict[str, Any] | None,
        stype: str | None,
    ) -> list[str]:
        """Keys of the outermost JSON container, for envelope inspection."""
        if not isinstance(struct, dict):
            return []
        if stype == "object":
            keys = struct.get("keys")
        elif stype == "array":
            keys = struct.get("item_keys")
        else:
            return []
        if not isinstance(keys, list):
            return []
        return [str(k) for k in keys]

    def _classify_api_behavior(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """Score observed behavior. `/api/` and JSON alone never confirm.

        A plain `{"name": "John"}` body is a candidate, not a confirmed API.
        Confirmation requires behavior that only an API would exhibit: a
        machine-readable error contract, GraphQL or SOAP framing, a served
        OpenAPI document, or auth/method gating that returns a structured
        body. Every signal that fired is reported as evidence.

        Evidence numbers are stable and unique so a reader can cite one.
        """
        struct = ctx["struct"]
        ct = ctx["content_type"]
        status = ctx["status"]
        body = ctx["body"]
        headers = ctx["headers"]
        options = ctx.get("options")

        stype = (
            struct.get("type")
            if isinstance(struct, dict)
            else None
        )

        if stype is None:
            return self._behavior(
                "uncertain",
                ["1: request failed or response body unavailable"],
            )

        # ---- categorically not an API --------------------------------
        if stype == "binary" or ct in _JS_CSS_TYPES:
            return self._behavior(
                "unlikely",
                ["2: static/binary or JavaScript/CSS response"],
            )

        if stype == "xml":
            feed = struct.get("feed")
            if feed:
                return self._behavior(
                    "unlikely",
                    [f"3: {feed.upper()} feed response, not an API"],
                )
            root = struct.get("root")
            detail = f" (root <{root}>)" if root else ""
            if struct.get("fault"):
                op = struct.get("operation")
                return self._behavior(
                    "confirmed",
                    [
                        "4: SOAP fault response"
                        + (f" (operation {op})" if op else "")
                    ],
                )
            if struct.get("soap"):
                op = struct.get("operation")
                return self._behavior(
                    "confirmed",
                    [
                        "4: SOAP envelope response"
                        + (f" (operation {op})" if op else "")
                        + detail
                    ],
                )
            return self._behavior(
                "uncertain",
                [
                    "5: XML response but no SOAP envelope" + detail
                ],
            )

        # ---- evidence scoring -----------------------------------------
        json_ct = _is_json_content(ct)
        container = self._parsed_container(struct)
        looks_json = container or (
            isinstance(body, str) and body.lstrip()[:1] in ("{", "[")
        )

        score = 0
        evidence: list[str] = []

        # Weak: a JSON content type is a hint, never a verdict.
        if json_ct:
            score += 1
            evidence.append(f"6: JSON content type ({ct})")

        # Weak: the body parsed into a JSON container.
        if container:
            score += 1
            evidence.append(f"7: parsed JSON {stype} in body")

        top_keys = self._top_level_keys(struct, stype)
        lowered_keys = {k.lower() for k in top_keys}

        # Weak-moderate: an API-shaped path. Explicitly NOT proof: it only
        # ever combines with an observed machine-readable response.
        path_signal = self._api_path_signal(ctx)
        if path_signal:
            score += 2
            evidence.append(
                f"8: API-style path segment {path_signal!r} "
                "(naming hint only, not proof on its own)"
            )

        # Strong: machine-readable API error envelope.
        envelope, envelope_is_strong = self._json_error_envelope(
            ctx, top_keys
        )
        evidence.extend(envelope)
        if envelope_is_strong:
            score += 2

        # Strong: GraphQL "data" + "errors" framing.
        if "data" in lowered_keys and ("errors" in lowered_keys):
            score += 3
            evidence.append(
                "10: GraphQL response envelope (top-level data + errors)"
            )

        # Strong: the body IS an OpenAPI/Swagger document.
        if (
            lowered_keys & _SPEC_VERSION_KEYS
            and _SPEC_PATHS_KEY in lowered_keys
        ):
            score += 3
            evidence.append(
                "11: OpenAPI/Swagger specification document "
                "(declares a paths map)"
            )

        # Moderate: pagination / collection wrapper.
        if lowered_keys & _PAGINATION_KEYS:
            score += 1
            evidence.append("12: pagination fields present")
        if lowered_keys & _DATA_WRAPPER_KEYS:
            score += 1
            evidence.append("13: data envelope wrapper key present")

        # ---- decisive API behaviours ----------------------------------
        if status in _AUTH_STATUSES and stype != "html":
            score += 1
            evidence.append(
                f"14: status {status} with a machine-readable body"
            )
            if headers.get("www-authenticate"):
                score += 2
                evidence.append(
                    "15: WWW-Authenticate header names an auth scheme"
                )
            if headers.get("allow"):
                score += 1
                evidence.append("16: Allow header lists methods")

        # A 405 plus a real Allow header is API-shaped method negotiation.
        if status == 405 and headers.get("allow"):
            score += 2
            evidence.append(
                f"17: 405 with Allow: "
                f"{self._truncate(headers['allow'], 80)}"
            )

        # OPTIONS evidence: an Allow list is an API method contract.
        if isinstance(options, dict):
            allowed = options.get("allowed_methods") or []
            interesting = [
                m for m in allowed
                if m not in ("GET", "HEAD", "OPTIONS")
            ]
            if allowed and interesting:
                score += 1
                evidence.append(
                    "18: OPTIONS advertises additional methods: "
                    + ", ".join(interesting[:6])
                )
            elif options.get("status") == 405:
                evidence.append("19: OPTIONS returned 405")

        # ---- redirect to login hides the real shape --------------------
        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(self._path_of(ctx["final_url"]))
        ):
            lines = [
                "20: redirected to a login/authentication path; "
                "the real API shape is not observable"
            ]
            if path_signal:
                lines.append(
                    f"21: requested API-style path {path_signal!r}"
                )
            return self._behavior("uncertain", lines)

        # ---- verdict ---------------------------------------------------
        if score >= CONFIRMED_SCORE:
            return self._behavior("confirmed", evidence)

        # ---- clearly not an API ---------------------------------------
        if stype == "html":
            line = "22: HTML page response (not a JSON API payload)"
            if path_signal:
                line += f" despite API-style path {path_signal!r}"
            return self._behavior("unlikely", [line])

        if json_ct and stype == "empty":
            evidence.append("23: JSON content type with empty body")
            return self._behavior("uncertain", evidence)

        if (ctx["truncated"] or ctx.get("deadline")) and looks_json:
            evidence.append(
                "24: body truncated while parsing JSON; evidence "
                "incomplete"
            )
            return self._behavior("uncertain", evidence)

        if stype == "unknown":
            reason = (
                struct.get("reason") if isinstance(struct, dict) else None
            )
            if reason == "incomplete_body":
                evidence.append(
                    "25: response body was incomplete, so JSON shape "
                    "could not be determined"
                )
            elif reason == "malformed_json":
                evidence.append(
                    "26: declared JSON but the body did not parse"
                )
            else:
                evidence.append(
                    "27: response format could not be determined"
                )
            return self._behavior("uncertain", evidence)

        if score >= LIKELY_SCORE:
            return self._behavior("likely", evidence)

        evidence.append(
            "28: JSON alone is not sufficient evidence of an "
            "API endpoint"
        )
        return self._behavior("uncertain", evidence)

    def _classify_access(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """FIRST MATCH WINS access classification."""
        status = ctx["status"]
        headers = ctx["headers"]

        if status == 401 or headers.get("www-authenticate"):
            ev: list[str] = []
            if status == 401:
                ev.append("1: status 401 Unauthorized")
            if headers.get("www-authenticate"):
                ev.append(
                    "1: WWW-Authenticate header: "
                    + self._truncate(headers["www-authenticate"], 80)
                )
            return {
                "classification": "authentication_required",
                "evidence": ev,
            }

        if status == 403:
            return {
                "classification": "forbidden",
                "evidence": ["2: status 403 Forbidden"],
            }

        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(self._path_of(ctx["final_url"]))
        ):
            return {
                "classification": "authentication_required",
                "evidence": [
                    "3: redirected to a login/authentication path"
                ],
            }

        if 200 <= status < 300:
            return {
                "classification": "public",
                "evidence": [
                    "4: 2xx response served without any credentials"
                ],
            }

        if status == 405:
            return {
                "classification": "public",
                "evidence": [
                    "5: endpoint exists and rejected the method; "
                    "no credentials were supplied"
                ],
            }

        return {
            "classification": "unknown",
            "evidence": ["6: no access signal matched"],
        }

    # -- security posture ----------------------------------------------------

    def _security_posture(
        self,
        ctx: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Passive, context-aware transport observations.

        This reports what was observed. It deliberately does not claim an
        endpoint is secure, and it does not treat the absence of
        browser-oriented headers on a JSON API as a finding.
        """
        headers = ctx["headers"]
        status = ctx["status"]
        ct = ctx["content_type"]
        final_url = ctx["final_url"]
        struct = ctx["struct"]
        stype = (
            struct.get("type") if isinstance(struct, dict) else None
        )

        try:
            scheme = urlsplit(final_url).scheme.lower()
        except (ValueError, UnicodeError):
            scheme = ""

        is_html = stype == "html" or ct == "text/html"
        is_api_like = stype in ("object", "array") or _is_json_content(ct)

        observations: list[dict[str, Any]] = []
        notes: list[str] = []

        def observe(
            category: str,
            title: str,
            detail: str,
            severity: str = "info",
        ) -> None:
            observations.append({
                "category": category,
                "title": title,
                "detail": detail,
                "severity": severity,
            })

        # Transport
        if scheme == "http":
            observe(
                "transport", "cleartext HTTP",
                "the endpoint was served over http:// with no "
                "transport encryption observed",
                "medium",
            )
        else:
            observe(
                "transport", "HTTPS in use",
                "the endpoint was served over https://",
            )

        hsts = headers.get("strict-transport-security")
        if scheme == "https" and not hsts:
            observe(
                "transport", "no HSTS header",
                "no Strict-Transport-Security header observed on a "
                "TLS response; browsers can be downgraded on the "
                "first request",
                "low",
            )
        elif hsts:
            observe(
                "transport", "HSTS present",
                self._truncate(hsts, MAX_HEADER_VALUE),
            )

        # Content-type protection
        nosniff = headers.get("x-content-type-options") or headers.get(
            "x-content-type-nosniff"
        )
        if nosniff and "nosniff" in nosniff.lower():
            observe(
                "content_type", "nosniff present",
                self._truncate(nosniff, MAX_HEADER_VALUE),
            )
        elif is_html:
            observe(
                "content_type", "no nosniff on an HTML response",
                "a browser may MIME-sniff this response; "
                "X-Content-Type-Options: nosniff is absent",
                "low",
            )

        # Clickjacking. Only meaningful for rendered documents: a JSON API
        # is not framed, so its absence is not reported as a finding.
        frame_options = headers.get("x-frame-options")
        csp = headers.get("content-security-policy") or ""
        frame_ancestors = "frame-ancestors" in csp.lower()
        if frame_options:
            observe(
                "clickjacking", "X-Frame-Options present",
                self._truncate(frame_options, MAX_HEADER_VALUE),
            )
        elif frame_ancestors:
            observe(
                "clickjacking", "CSP frame-ancestors present",
                "the content security policy restricts framing",
            )
        elif is_html:
            observe(
                "clickjacking", "no framing protection",
                "neither X-Frame-Options nor a CSP frame-ancestors "
                "directive was observed on a rendered page",
                "low",
            )

        # CORS
        acao = headers.get("access-control-allow-origin")
        credentials = (
            headers.get("access-control-allow-credentials") or ""
        ).lower() == "true"
        if acao:
            if acao.strip() == "*" and credentials:
                observe(
                    "cors", "permissive CORS with credentials",
                    "Access-Control-Allow-Origin is '*' together with "
                    "Access-Control-Allow-Credentials: true, a "
                    "contradictory combination browsers reject",
                    "medium",
                )
            elif acao.strip() == "*":
                observe(
                    "cors", "wildcard CORS",
                    "any origin may read this response",
                )
            else:
                observe(
                    "cors", "origin-scoped CORS",
                    "Access-Control-Allow-Origin: "
                    + self._truncate(acao, MAX_HEADER_VALUE),
                )
        if credentials:
            observe(
                "cors", "CORS credentials allowed",
                "cross-origin requests may include credentials",
                "low",
            )

        # Caching of sensitive responses
        cache_control = headers.get("cache-control")
        if status in _AUTH_STATUSES or self._looks_sensitive(result):
            if not cache_control:
                observe(
                    "caching", "no Cache-Control on a sensitive response",
                    "a restricted or sensitive response was served "
                    "without an explicit caching directive",
                    "low",
                )
            elif "no-store" not in cache_control.lower() and (
                "private" not in cache_control.lower()
            ):
                observe(
                    "caching", "sensitive response may be cached",
                    "Cache-Control is "
                    + self._truncate(cache_control, MAX_HEADER_VALUE),
                    "low",
                )
        elif cache_control:
            observe(
                "caching", "Cache-Control present",
                self._truncate(cache_control, MAX_HEADER_VALUE),
            )

        # Informational API/behaviour headers
        for header, category, title in (
            ("retry-after", "api", "Retry-After present"),
            ("server-timing", "api", "Server-Timing present"),
            ("etag", "api", "ETag present"),
            ("vary", "api", "Vary present"),
        ):
            value = headers.get(header)
            if value:
                observe(
                    category, title,
                    self._truncate(value, MAX_HEADER_VALUE),
                )

        server = headers.get("server")
        if server:
            observe(
                "disclosure", "Server header present",
                self._truncate(server, MAX_HEADER_VALUE),
            )
        powered = headers.get("x-powered-by")
        if powered:
            observe(
                "disclosure", "X-Powered-By present",
                self._truncate(powered, MAX_HEADER_VALUE),
            )

        referrer = headers.get("referrer-policy")
        if referrer:
            observe(
                "privacy", "Referrer-Policy present",
                self._truncate(referrer, MAX_HEADER_VALUE),
            )

        if not is_html and not is_api_like:
            notes.append(
                "response is neither a rendered page nor a JSON API; "
                "browser-oriented header checks were not applied"
            )

        counts: dict[str, int] = {}
        for obs in observations:
            sev = obs["severity"]
            counts[sev] = counts.get(sev, 0) + 1

        return {
            "transport_encrypted": scheme == "https",
            "observations": observations,
            "observation_counts": counts,
            "context": {
                "rendered_html": bool(is_html),
                "api_like": bool(is_api_like),
            },
            "notes": notes,
        }

    @staticmethod
    def _looks_sensitive(result: dict[str, Any]) -> bool:
        """True when the request or the response carried sensitive data.

        Includes body findings, so an endpoint that returned a live token is
        treated as sensitive even when no query parameter was involved.
        """
        params = result.get("parameters") or []
        if any(p.get("sensitive") for p in params):
            return True
        findings = result.get("sensitive_findings") or []
        return any(
            f.get("type") in (
                "sensitive_field",
                "sensitive_header",
                "sensitive_parameter",
            )
            for f in findings
        )

    # -- result scaffolding --------------------------------------------------

    @staticmethod
    def _behavior(
        classification: str,
        evidence: list[str],
    ) -> dict[str, Any]:
        return {
            "classification": classification,
            "evidence": evidence,
        }

    def _path_of(self, url: str) -> str:
        try:
            return urlsplit(url).path or ""
        except (ValueError, UnicodeError):
            return ""

    @staticmethod
    def _new_result() -> dict[str, Any]:
        """Canonical single-schema result with neutral defaults."""
        return {
            "url": None,
            "source": SOURCE_DEFAULT,
            "found_in": None,
            "requested_method": None,
            "method": None,
            "status": None,
            "status_category": None,
            "content_type": None,
            "parameters": [],
            "url_context": {},
            "response_structure": None,
            "json_analysis": None,
            "final_url": None,
            "redirected": False,
            "redirect_chain": [],
            "redirect_details": [],
            "response_time_ms": None,
            "response_size": None,
            "response_size_truncated": False,
            "headers": {h: None for h in _CAPTURED_HEADERS},
            "options": None,
            "api_behavior": {
                "classification": "uncertain",
                "evidence": [],
            },
            "access": {
                "classification": "unknown",
                "evidence": [],
            },
            "security_posture": None,
            "sensitive_findings": [],
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
    """Build an EndpointAnalyzer, analyze the file, always close."""
    analyzer = EndpointAnalyzer(**options)
    try:
        return analyzer.analyze_discovery_file(
            input_path, output_path
        )
    finally:
        analyzer.close()


def _self_test() -> int:
    """Assert-based checks for the logic that is easy to break silently.

    Runs offline except for one loopback HTTP round trip, which is what
    proves the read/redirect/classification path still works end to end.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            failures.append(name)

    with EndpointAnalyzer(request_delay=0) as an:
        # 1. Envelope/status keys are NOT secrets. This is the regression
        #    that made every API report a false data-exposure finding.
        for key in ("code", "status_code", "error_code", "country_code",
                    "author", "page", "user", "id"):
            check(f"{key} must not be sensitive",
                  not an._is_sensitive_key(key))
        # 2. Real credentials are still caught.
        for key in ("api_key", "password", "token", "authorization_code",
                    "authToken", "client_secret", "accessToken"):
            check(f"{key} must be sensitive", an._is_sensitive_key(key))

        # 3. URL policy: userinfo, odd schemes and bad ports are rejected.
        check("userinfo rejected",
              an._parse_http_url("https://u:p@x.com/") is None)
        check("file scheme rejected",
              an._parse_http_url("file:///etc/passwd") is None)
        err = an._validate_resolved(
            ("https", "u:p@x.com", "/", "", "")
        )
        check("userinfo caught by validator", err is not None)
        err = an._validate_resolved(("ftp", "x.com", "/", "", ""))
        check("ftp rejected by validator",
              err is not None and err["type"] == "unsupported_scheme")

        # 4. Display and transmission stay independent.
        red = EndpointAnalyzer(redact_sensitive=True, request_delay=0)
        sent = EndpointAnalyzer(
            redact_sensitive=False, send_sensitive_params=True,
            request_delay=0,
        )
        try:
            url = "http://x/api?api_key=SECRETVALUE&page=2"
            check("redacted display",
                  "REDACTED" in red._display_url(url))
            check("redaction does not stop the request",
                  red._sanitize_query(url)[1] is True)
            check("send authorized keeps the value",
                  sent._sanitize_query(url) == (url, False))
        finally:
            red.close()
            sent.close()

        # 5. Redirect policy: cross-host is refused, loop detection is
        #    order-insensitive, http->https on default ports is allowed.
        nxt, why = an._resolve_redirect(
            "http://a.com/x", "http://evil.com/y", ("http", "a.com", 80)
        )
        check("cross-host redirect refused", nxt is None and why)
        nxt, why = an._resolve_redirect(
            "http://a.com/x", "https://a.com/y", ("http", "a.com", 80)
        )
        check("http->https upgrade allowed", nxt is not None)
        nxt, why = an._resolve_redirect(
            "http://a.com/x", "http://a.com:8080/y", ("http", "a.com", 80)
        )
        check("port change refused", nxt is None)
        k1 = an._canonical_for_loop_check("http://A.com/p?a=1&b=2")
        k2 = an._canonical_for_loop_check("http://a.com/p?b=2&a=1#frag")
        check("loop key is canonical", k1 == k2)

        # 6. Structure inference and the classification contract.
        check("json object inferred",
              an._infer_structure({"a": 1}, 1)["type"] == "object")
        check("array item keys inferred",
              an._infer_structure([{"a": 1}], 1)["item_keys"] == ["a"])
        ctx = {
            "status": 200, "content_type": "application/json",
            "struct": an._infer_structure({"id": 1, "name": "J"}, 1),
            "body": '{"id":1}', "headers": {}, "chain": ["u"],
            "final_url": "http://x/thing", "initial_url": "http://x/thing",
            "truncated": False, "deadline": False,
            "followed_same_host": False, "options": None, "json_ok": True,
        }
        check("plain JSON is not confirmed",
              an._classify_api_behavior(ctx)["classification"]
              != "confirmed")
        check("plain JSON is still evidence-backed",
              an._classify_api_behavior(ctx)["evidence"])

        # 7. XML families.
        rss = an._parse_xml_structure(
            "<rss><channel><item/></channel></rss>"
        )
        check("rss feed detected", (rss or {}).get("feed") == "rss")
        # The namespace must be declared or ElementTree correctly refuses
        # the document (an undeclared prefix is a parse error, not a fault).
        soap = an._parse_xml_structure(
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/'
            'envelope/"><s:Body><GetIt/></s:Body></s:Envelope>'
        )
        check("soap envelope detected", (soap or {}).get("soap") is True)
        check("undeclared prefix is refused, not guessed",
              an._parse_xml_structure("<s:Envelope/>") is None)
        check("xxe is not expanded",
              an._parse_xml_structure(
                  '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                  "<r>&x;</r>"
              ) is None)

        # 8. Evidence numbers are unique within one verdict, so a reader can
        #    cite one number without ambiguity.
        ctx2 = dict(ctx, struct=an._infer_structure(
            {"code": 1, "error_code": "E", "message": "m", "data": [],
             "errors": [], "page": 1}, 1), status=400,
            headers={"www-authenticate": "Bearer", "allow": "GET,POST"})
        nums = [
            int(e.split(":")[0]) for e in
            an._classify_api_behavior(ctx2)["evidence"]
            if e[:1].isdigit()
        ]
        check("evidence numbers are unique", len(nums) == len(set(nums)))

    # 9. One real round trip: classification over a live response.
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/api/leak":
                body = json.dumps(
                    {"accessToken": "AKIAIOSFODNN7EXAMPLE1234"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif self.path == "/api/ok":
                body = json.dumps(
                    {"code": 0, "message": "ok", "data": [{"id": 1}]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            else:
                body = b'{"error":"nope"}'
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with EndpointAnalyzer(request_delay=0) as an:
            ok = an.analyze_endpoint({"url": base + "/api/ok"})
            check("live request reached the server", ok["status"] == 200)
            check("benign envelope raises no finding",
                  ok["sensitive_findings"] == [])
            leak = an.analyze_endpoint({"url": base + "/api/leak"})
            check("real token still reported",
                  any(f["type"] == "sensitive_field"
                      for f in leak["sensitive_findings"]))
            denied = an.analyze_endpoint({"url": base + "/nope"})
            check("401 classified as auth required",
                  denied["access"]["classification"]
                  == "authentication_required")
            for bad in (None, "", 123, {"nope": 1}, "http://[::1"):
                r = an.analyze_endpoint(bad)
                check(f"bad candidate {bad!r} reports an error",
                      isinstance(r, dict) and r["error"] is not None)
    finally:
        srv.shutdown()

    if failures:
        print("SELF-TEST FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("self-test: all checks passed")
    return 0


def main(argv: list[str]) -> int:
    """Minimal entry point: analyze a discovery JSON file."""
    args = argv[1:]

    if args and args[0] in ("--self-test", "--self_test"):
        return _self_test()

    if not args:
        print(
            "usage: python endpoint_analysis.py "
            "<discovery.json> [analysis.json]\n"
            "       python endpoint_analysis.py --self-test",
            file=sys.stderr,
        )
        return 1

    input_path = args[0]
    output_path = args[1] if len(args) > 1 else None

    try:
        results = analyze_discovery_file(input_path, output_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"error: {type(exc).__name__}: "
            f"{exc.strerror or exc}",
            file=sys.stderr,
        )
        return 1

    if output_path is None:
        print(
            json.dumps(results, ensure_ascii=True, indent=2, default=str)
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
