"""Shared async HTTP for collectors and enrichers: one httpx client, an on-disk cache, throttling."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from cartograph.cache import ResponseCache

#: transient HTTP statuses worth retrying (rate-limit + gateway/backend errors)
RETRYABLE_STATUS: tuple[int, ...] = (429, 502, 503, 504)


class AsyncFetcher:
    """Base for anything that fetches from public HTTP sources with caching + throttling."""

    #: short, stable identifier; also used as the cache namespace and provenance tag
    name: str = "base"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        cache: ResponseCache | None = None,
        min_interval: float = 1.0,
        timeout: float = 20.0,
        retries: int = 2,
        backoff: float = 1.0,
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self.cache = cache or ResponseCache()
        self.min_interval = min_interval
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._last_request = 0.0

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"User-Agent": "cartograph/0.0.1 (+passive-osint)"},
                follow_redirects=True,
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _throttle(self) -> None:
        loop = asyncio.get_event_loop()
        elapsed = loop.time() - self._last_request
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        self._last_request = loop.time()

    async def get_json(
        self,
        url: str,
        *,
        cache_key: str | None = None,
        allow_status: tuple[int, ...] = (),
        headers: dict[str, str] | None = None,
    ) -> Any:
        """GET ``url`` as JSON, cache-first and throttled.

        ``allow_status`` lists non-2xx codes to treat as an empty result (returns ``None``) instead
        of raising – useful for sources that return 404 for "nothing found".
        """
        key = cache_key or url
        cached = self.cache.get(self.name, key)
        if cached is not None:
            return cached
        resp = await self._get_with_retry(url, headers=headers)
        if resp.status_code in allow_status:
            return None
        resp.raise_for_status()
        data = resp.json()
        self.cache.set(self.name, key, data)
        return data

    async def _get_with_retry(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        """GET with retries on timeouts and transient server statuses (429/502/503/504).

        These are the failures that clear on their own (a slow or briefly-overloaded public API –
        crt.sh in particular loves a 502). Connection errors like NXDOMAIN are *not* retried: a
        missing host won't reappear, and retrying just wastes time.
        """
        last_exc: httpx.TimeoutException | None = None
        resp: httpx.Response | None = None
        for attempt in range(self.retries + 1):
            await self._throttle()
            try:
                resp = await self.client.get(url, headers=headers)
            except httpx.TimeoutException as exc:
                last_exc = exc
                if attempt < self.retries:
                    await asyncio.sleep(self.backoff * (attempt + 1))
                continue
            if resp.status_code in RETRYABLE_STATUS and attempt < self.retries:
                await asyncio.sleep(self.backoff * (attempt + 1))
                continue
            return resp
        if resp is not None:
            return resp
        assert last_exc is not None
        raise last_exc
