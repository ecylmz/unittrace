from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


SYSTEM_UNIT_PREFIXES = (
    "lib/systemd/system/",
    "usr/lib/systemd/system/",
    "etc/systemd/system/",
)

UNIT_SUFFIXES = (".service", ".service.d/")


def is_system_service_path(path: str) -> bool:
    normalized = path.lstrip("./")
    return normalized.startswith(SYSTEM_UNIT_PREFIXES) and (
        normalized.endswith(".service") or ".service.d/" in normalized
    )


def normalize_upstream_url(url: str) -> str | None:
    value = url.strip().split()[0] if url.strip() else ""
    if not value or value.lower() in {"none", "unknown"}:
        return None
    if value.startswith("git@") and ":" in value:
        host, path = value[4:].split(":", 1)
        value = f"https://{host}/{path}"
    if "://" not in value:
        return None
    split = urlsplit(value)
    host = split.hostname.lower() if split.hostname else ""
    aliases = {"www.github.com": "github.com", "gitlab.com": "gitlab.com", "www.gitlab.com": "gitlab.com"}
    host = aliases.get(host, host)
    path = re.sub(r"/+", "/", split.path).rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if host == "github.com" and len(path.strip("/").split("/")) >= 2:
        path = "/" + "/".join(path.strip("/").split("/")[:2])
    return urlunsplit(("https", host, path, "", ""))


def deterministic_order(canonical_upstream_id: str, namespace: str) -> str:
    material = namespace.encode() + b"\0" + canonical_upstream_id.encode()
    return hashlib.sha256(material).hexdigest()


def normalized_exec_lineage(exec_start: str) -> str | None:
    value = exec_start.strip()
    if not value:
        return None
    value = re.sub(r"^[+!:@-]+", "", value)
    token = value.split()[0]
    token = token.replace("${", "{")
    if any(marker in token for marker in ("%", "$", "{")):
        return None
    return Path(token).name or None

