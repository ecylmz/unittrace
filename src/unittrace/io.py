from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        stream.write(payload)
        temporary = Path(stream.name)
    os.replace(temporary, path)


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def download(url: str, destination: Path, expected_sha256: str | None = None) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        digest = sha256_file(destination)
        if expected_sha256 is None or digest == expected_sha256:
            retrieved_at = datetime.fromtimestamp(destination.stat().st_mtime, timezone.utc).isoformat()
            return {"url": url, "path": str(destination), "sha256": digest, "bytes": destination.stat().st_size, "cached": True, "retrieved_at_utc": retrieved_at}
        destination.unlink()
    request = urllib.request.Request(url, headers={"User-Agent": "UnitTrace-Phase0R/0.1"})
    with urllib.request.urlopen(request, timeout=180) as response:
        with tempfile.NamedTemporaryFile("wb", dir=destination.parent, delete=False) as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
            temporary = Path(stream.name)
    digest = sha256_file(temporary)
    if expected_sha256 is not None and digest != expected_sha256:
        temporary.unlink()
        raise ValueError(f"SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}")
    os.replace(temporary, destination)
    retrieved_at = datetime.fromtimestamp(destination.stat().st_mtime, timezone.utc).isoformat()
    return {"url": url, "path": str(destination), "sha256": digest, "bytes": destination.stat().st_size, "cached": False, "retrieved_at_utc": retrieved_at}


def jsonl_append(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(row), sort_keys=True) + "\n")
