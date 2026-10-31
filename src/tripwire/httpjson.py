from __future__ import annotations

import json
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

Fetch = Callable[[str], Tuple[bytes, str]]  # url -> (body, Link header)


def urlopen_fetch(headers: Dict[str, str]) -> Fetch:
    def fetch(url: str) -> Tuple[bytes, str]:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read(), resp.headers.get("Link", "")

    return fetch


def next_link(link: str) -> Optional[str]:
    for part in link.split(","):
        if 'rel="next"' in part and "<" in part:
            return part[part.index("<") + 1 : part.index(">")]
    return None


def get_all(fetch: Fetch, url: Optional[str]) -> List[dict]:
    """GET a URL and follow Link rel=next; a single object becomes a 1-item list."""
    items: List[dict] = []
    while url:
        body, link = fetch(url)
        data = json.loads(body)
        items.extend(data if isinstance(data, list) else [data])
        url = next_link(link)
    return items
