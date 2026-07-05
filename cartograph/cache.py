"""On-disk response cache: avoids refetching, and lets a run replay from a snapshot without network."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ResponseCache:
    """Simple keyed JSON cache under a directory (default: ``.cache/``)."""

    def __init__(self, root: str | Path = ".cache") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        ns_dir = self.root / namespace
        ns_dir.mkdir(parents=True, exist_ok=True)
        return ns_dir / f"{digest}.json"

    def get(self, namespace: str, key: str) -> Any | None:
        path = self._path(namespace, key)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def set(self, namespace: str, key: str, value: Any) -> None:
        self._path(namespace, key).write_text(
            json.dumps(value, ensure_ascii=False), encoding="utf-8"
        )
