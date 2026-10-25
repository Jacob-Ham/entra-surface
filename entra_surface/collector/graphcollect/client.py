"""HTTP clients for Microsoft Graph and Azure Resource Manager.

Paging + retry (429/5xx); failed calls raise Degraded and collectors skip
that section. Each thread gets its own keep-alive session so parallel
collection reuses TLS connections. Graph JSON batching is available through
``batch_paged_many`` for independent relationship collections.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterator, Optional
from urllib.parse import urljoin

import requests

GRAPH_BASE = "https://graph.microsoft.com"
GRAPH_BATCH_LIMIT = 20
GRAPH_BATCH_WORKERS = 2


class Degraded(Exception):
    """Raised when an endpoint fails; collectors skip that section."""

    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"{status} {url} {body[:200]}")


class BatchPagedResult:
    """Collected items and error state for one URL in a Graph batch."""

    def __init__(self):
        self.items: list[dict] = []
        self.error = ""
        self.status = 0
        self.body = ""


class GraphClient:
    def __init__(self, token_getter: Callable[[], str], verbose: int = 0,
                 user_agent: Optional[str] = None, batch: bool = False,
                 batch_size: int = GRAPH_BATCH_LIMIT):
        self._token_getter = token_getter
        self.verbose = verbose
        self.user_agent = user_agent
        self.batch = bool(batch)
        self.batch_size = max(1, min(int(batch_size or GRAPH_BATCH_LIMIT),
                                     GRAPH_BATCH_LIMIT))
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.requests_made = 0
        self.subrequests_made = 0
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

    def _headers(self) -> dict:
        headers = {"Authorization": f"Bearer {self._token_getter()}"}
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        return headers

    @staticmethod
    def _retry_after(headers, default: int = 5) -> int:
        headers = headers or {}
        try:
            value = int(headers.get("Retry-After")
                        or headers.get("retry-after") or default)
        except (TypeError, ValueError):
            value = default
        return max(0, min(value, 60))

    def request(self, method: str, url: str, retries: int = 5,
                timeout: int = 60) -> requests.Response:
        for attempt in range(retries):
            try:
                r = self._session().request(
                    method, url, headers=self._headers(), timeout=timeout)
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
                wait = self._retry_after(r.headers)
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

    # -- JSON batching --------------------------------------------------------
    def _batch_post(self, api: str, entries: list[dict]) -> list[dict]:
        """POST one JSON batch and return the raw response list."""
        if not entries:
            return []
        url = f"{GRAPH_BASE}/{api}/$batch"
        prefix = f"{GRAPH_BASE}/{api}"
        subrequests = []
        for index, entry in enumerate(entries):
            sub_url = entry["url"]
            if sub_url.startswith(prefix):
                sub_url = sub_url[len(prefix):] or "/"
            subrequests.append({
                "id": str(index), "method": "GET",
                "url": sub_url.replace(" ", "%20"),
            })
        payload = {"requests": subrequests}
        for attempt in range(5):
            headers = self._headers()
            headers["Content-Type"] = "application/json"
            headers["Accept"] = "application/json"
            try:
                response = self._session().post(
                    url, json=payload, headers=headers, timeout=120)
            except requests.RequestException:
                if attempt == 4:
                    raise Degraded(0, url, "batch request failed")
                time.sleep(1 + attempt)
                continue
            with self._count_lock:
                self.requests_made += 1
                self.subrequests_made += len(entries)
            if response.status_code == 429:
                with self._count_lock:
                    self.throttled += 1
                wait = self._retry_after(response.headers)
                time.sleep(min(wait, 60) + 1)
                continue
            if response.status_code in (500, 502, 503, 504) and attempt < 4:
                time.sleep(1 + attempt)
                continue
            if response.status_code != 200:
                raise Degraded(response.status_code, url,
                               response.text[:500])
            try:
                data = response.json()
            except ValueError:
                raise Degraded(response.status_code, url,
                               "invalid batch response")
            responses = data.get("responses")
            if not isinstance(responses, list):
                raise Degraded(response.status_code, url,
                               "missing batch responses")
            if self.verbose >= 2:
                print(f"[graph] batch {len(entries)} -> {url}")
            return responses
        raise Degraded(0, url, "batch retries exhausted")

    def batch_paged_many(self, batch_requests: list[dict],
                         max_pages: int = 5000) -> dict[str, BatchPagedResult]:
        """Fetch independent paged collections in Graph JSON batches.

        ``batch_requests`` entries need a unique ``key``, a ``path`` and an
        optional ``api`` (default v1.0). Pages from all keys are fetched in
        rounds, with at most Graph's 20-subrequest limit per batch.
        """
        pending: dict[str, dict] = {}
        results: dict[str, BatchPagedResult] = {}
        for request in batch_requests:
            key = str(request["key"])
            api = str(request.get("api") or "v1.0")
            path = str(request["path"])
            url = (path if path.startswith("http")
                   else f"{GRAPH_BASE}/{api}{path}")
            pending[key] = {
                "api": api,
                "urls": [url],
                "pages": 0,
                "attempts": 0,
            }
            results[key] = BatchPagedResult()

        while pending:
            groups: dict[str, list[dict]] = {}
            for key, state in list(pending.items()):
                if not state["urls"]:
                    del pending[key]
                    continue
                url = state["urls"].pop(0)
                groups.setdefault(state["api"], []).append({
                    "key": key, "url": url})
            if not groups:
                break

            wait = 0
            chunks = []
            for api, entries in groups.items():
                for offset in range(0, len(entries), self.batch_size):
                    chunks.append((api, entries[offset:offset + self.batch_size]))
            with ThreadPoolExecutor(
                    max_workers=min(GRAPH_BATCH_WORKERS, len(chunks) or 1)) as ex:
                futures = [(chunk, ex.submit(self._batch_post, api, chunk))
                           for api, chunk in chunks]
                for chunk, future in futures:
                    try:
                        responses = future.result()
                    except Degraded as exc:
                        for entry in chunk:
                            result = results[entry["key"]]
                            result.error = str(exc)
                            result.status = exc.status
                            result.body = exc.body
                        continue
                    by_id = {str(item.get("id")): item
                             for item in responses if isinstance(item, dict)}
                    for index, entry in enumerate(chunk):
                        key = entry["key"]
                        state = pending.get(key)
                        result = results[key]
                        if state is None:
                            continue
                        item = by_id.get(str(index), {})
                        status = int(item.get("status") or 0)
                        headers = item.get("headers") or {}
                        body = item.get("body")
                        if status == 200:
                            if isinstance(body, dict):
                                if isinstance(body.get("value"), list):
                                    result.items.extend(body.get("value") or [])
                                elif body:
                                    result.items.append(body)
                                link = body.get("@odata.nextLink")
                                if link:
                                    if not str(link).startswith("http"):
                                        link = urljoin(entry["url"], str(link))
                                    if state["pages"] >= max_pages:
                                        result.error = "pagination cap reached"
                                        state["urls"] = []
                                    else:
                                        state["urls"].append(link)
                                        state["pages"] += 1
                            elif isinstance(body, list):
                                result.items.extend(body)
                        elif status == 429:
                            with self._count_lock:
                                self.throttled += 1
                            retry = self._retry_after(headers)
                            wait = max(wait, min(retry, 60))
                            state["attempts"] += 1
                            if state["attempts"] > 5:
                                result.status = status
                                result.error = f"429 {entry['url']}"
                                result.body = str(body)[:500]
                            else:
                                state["urls"].append(entry["url"])
                        elif status in (500, 502, 503, 504):
                            state["attempts"] += 1
                            if state["attempts"] > 5:
                                result.status = status
                                result.error = f"{status} {entry['url']}"
                                result.body = str(body)[:500]
                            else:
                                wait = max(wait, min(1 + state["attempts"], 30))
                                state["urls"].append(entry["url"])
                        else:
                            result.status = status
                            result.error = f"{status} {entry['url']}"
                            result.body = str(body)[:500] if body else ""
            if wait:
                time.sleep(wait + 1)
            pending = {key: state for key, state in pending.items()
                       if state["urls"]}
        return results



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
