"""TLS helpers for collector HTTP sessions."""
from __future__ import annotations

import ssl

import requests


class InsecureTLSAdapter(requests.adapters.HTTPAdapter):
    """HTTPAdapter that also skips certificate checks for HTTPS proxies."""

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if str(proxy).lower().startswith("https://"):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            proxy_kwargs.setdefault("proxy_ssl_context", context)
            proxy_kwargs.setdefault("proxy_assert_hostname", False)
        return super().proxy_manager_for(proxy, **proxy_kwargs)
