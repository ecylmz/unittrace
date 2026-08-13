from __future__ import annotations

import gzip
import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    manifest = json.loads((ROOT / "COMPRESSED_FILES.json").read_text(encoding="utf-8"))
    for record in manifest["files"]:
        source = ROOT / record["compressed_path"]
        destination = ROOT / record["original_path"]
        if sha256(source) != record["compressed_sha256"]:
            raise RuntimeError(f"compressed input hash mismatch: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(source, "rb") as input_stream, destination.open("wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
        if destination.stat().st_size != record["original_bytes"] or sha256(destination) != record["original_sha256"]:
            raise RuntimeError(f"restored input hash mismatch: {destination}")
        print(f"restored {destination.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
