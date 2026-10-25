"""HTTP clients for Microsoft Graph and Azure Resource Manager.

Paging + retry (429/5xx); failed calls raise Degraded and collectors skip
that section. Each thread gets its own keep-alive session so parallel
collection reuses TLS connections.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Iterator, Optional

import requests

GRAPH_BASE = "https://graph.microsoft.com"


class Degraded(Exception):
    """Raised when an endpoint fails; collectors skip that section."""

    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"{status} {url} {body[:200]}")


class GraphClient:
    def __init__(self, token_getter: Callable[[], str], verbose: int = 0,
                 user_agent: Optional[str] = None):
        self._token_getter = token_getter
        self.verbose = verbose
        self.user_agent = user_agent
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.requests_made = 0
        self.throttled = 0

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=16, pool_maxsize=32, max_retries=0)
            s.mount("https://", adapter)
            self._local.session = s
        return s

    def request(self, method: str, url: str, retries: int = 5,
                timeout: int = 60) -> requests.Response:
        for attempt in range(retries):
            headers = {"Authorization": f"Bearer {self._token_getter()}"}
            if self.user_agent:
                headers["User-Agent"] = self.user_agent
            try:
                r = self._session().request(method, url, headers=headers,
                                            timeout=timeout)
            except requests.RequestException:
                if attempt == retries - 1:
                    raise
                time.sleep(1 + attempt)
                continue
            with self._count_lock:
                self.requests_made += 1
            if r.status_code == 429:
                with self._count_lock:
                    self.throttled += 1
                wait = int(r.headers.get("Retry-After", "5") or 5)
                time.sleep(min(wait, 60) + 1)
                continue
            if r.status_code in (500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(1 + attempt)
                continue
            return r
        raise Degraded(0, url, "retries exhausted")

    def get(self, path: str, api: str = "v1.0") -> requests.Response:
        url = path if path.startswith("http") else f"{GRAPH_BASE}/{api}{path}"
        r = self.request("GET", url)
        if self.verbose >= 2:
            print(f"[graph] {r.status_code} {url}")
        return r

    def paged(self, path: str, api: str = "v1.0",
              max_pages: int = 5000) -> Iterator[dict]:
        """Yield items from a collection, following @odata.nextLink."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}/{api}{path}"
        pages = 0
        while url:
            r = self.request("GET", url)
            if r.status_code != 200:
                raise Degraded(r.status_code, url, r.text)
            data = r.json()
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")
            pages += 1
            if pages >= max_pages:
                raise Degraded(0, path, "pagination cap reached")


class ArmClient:
    def __init__(self, token_getter: Callable[[], str], verbose: int = 0,
                 user_agent: Optional[str] = None):
        self._token_getter = token_getter
        self.verbose = verbose
        self.user_agent = user_agent
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.requests_made = 0

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=8, pool_maxsize=16, max_retries=0)
            s.mount("https://", adapter)
            self._local.session = s
        return s

    def get(self, url: str, retries: int = 4) -> requests.Response:
        for attempt in range(retries):
            headers = {"Authorization": f"Bearer {self._token_getter()}"}
            if self.user_agent:
                headers["User-Agent"] = self.user_agent
            try:
                r = self._session().get(url, headers=headers, timeout=90)
            except requests.RequestException:
                if attempt == retries - 1:
                    raise
                time.sleep(1 + attempt)
                continue
            with self._count_lock:
                self.requests_made += 1
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", "5") or 5)
                time.sleep(min(wait, 60) + 1)
                continue
            if r.status_code in (500, 502, 503, 504) and attempt < retries - 1:
                time.sleep(1 + attempt)
                continue
            if self.verbose >= 2:
                print(f"[arm] {r.status_code} {url}")
            return r
        raise Degraded(0, url, "retries exhausted")
