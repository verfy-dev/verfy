"""``verfy self-verify``: is the Verfy that runs here the one verfy-dev/verfy published?

Four checks, each printed with its result:

1. every installed file still has the hash pip recorded when it installed it (``RECORD``);
2. the wheel PyPI serves for this version has the hash PyPI lists for it;
3. every installed file has the hash the wheel's own ``RECORD`` gives it, so nothing was changed after download;
4. PyPI holds a provenance attestation for that wheel from GitHub, repository verfy-dev/verfy, workflow publish.yml,
   whose statement names the same wheel hash.

What it does not do: check the Sigstore signature of the attestation itself (PyPI checked it when it accepted the
upload). ``pypi-attestations verify pypi`` does that too; the command is printed. A standalone build (no pip install)
is checked with the SHA256SUMS of its release instead.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import urllib.request
import zipfile
from typing import Any, Callable

PYPI = "https://pypi.org"
REPOSITORY, WORKFLOW = "verfy-dev/verfy", "publish.yml"


def _get(url: str, accept: str | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "verfy-self-verify", **({"Accept": accept} if accept else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URLs)
        return r.read()


def record_hash(data: bytes) -> str:
    """A file hash as a wheel RECORD writes it."""
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _record(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        parts = line.rsplit(",", 2)
        if len(parts) == 3 and parts[1].startswith("sha256="):
            out[parts[0].strip('"')] = parts[1]
    return out


def installed_files() -> tuple[str, dict[str, str], dict[str, bytes]] | None:
    """(version, RECORD hashes, file contents) of the pip-installed verfy, or None when it was not installed by pip."""
    try:
        from importlib import metadata
        dist = metadata.distribution("verfy")
    except Exception:  # noqa: BLE001
        return None
    record, contents = {}, {}
    for f in dist.files or []:
        if f.hash is None or f.hash.mode != "sha256":
            continue
        record[str(f).replace("\\", "/")] = "sha256=" + f.hash.value
        try:
            contents[str(f).replace("\\", "/")] = f.locate().read_bytes()
        except OSError:
            contents[str(f).replace("\\", "/")] = b""
    return dist.version, record, contents


def check(version: str, record: dict[str, str], contents: dict[str, bytes], get: Callable[..., bytes] = _get) -> dict[str, Any]:
    rows: list[tuple[bool, str]] = []

    if not record:
        rows.append((False, "pip recorded no file hashes for this install (an editable or source install), so it cannot be checked"))
        return {"ok": False, "rows": rows}
    changed = sorted(p for p, h in record.items() if record_hash(contents.get(p, b"")) != h)
    rows.append((not changed, f"{len(record)} installed files match the hashes pip recorded" if not changed
                 else f"{len(changed)} installed file(s) changed after install: " + ", ".join(changed[:5])))

    meta = json.loads(get(f"{PYPI}/pypi/verfy/{version}/json"))
    wheels = [u for u in meta.get("urls", []) if u.get("packagetype") == "bdist_wheel"]
    if not wheels:
        rows.append((False, f"PyPI has no wheel for verfy {version}"))
        return {"ok": False, "rows": rows}
    wheel = wheels[0]
    blob = get(wheel["url"])
    digest = hashlib.sha256(blob).hexdigest()
    rows.append((digest == wheel["digests"]["sha256"], f"{wheel['filename']} from PyPI has sha256 {digest[:16]}…"
                 + ("" if digest == wheel["digests"]["sha256"] else f", but PyPI lists {wheel['digests']['sha256'][:16]}…")))

    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        name = next(n for n in z.namelist() if n.endswith(".dist-info/RECORD"))
        # the code; pip rewrites part of the .dist-info folder (RECORD, INSTALLER), so that is left out
        published = {p: h for p, h in _record(z.read(name).decode("utf-8")).items() if ".dist-info/" not in p}
    differ = sorted(p for p, h in published.items() if p in record and record[p] != h)
    missing = sorted(p for p in published if p not in record)
    rows.append((not differ and not missing, f"every installed file matches the published wheel ({len(published)} files)" if not differ and not missing
                 else "installed files differ from the published wheel: " + ", ".join((differ + missing)[:5])))

    try:
        prov = json.loads(get(f"{PYPI}/integrity/verfy/{version}/{wheel['filename']}/provenance", "application/vnd.pypi.integrity.v1+json"))
    except Exception as e:  # noqa: BLE001
        rows.append((False, f"no provenance attestation on PyPI for {wheel['filename']} ({e})"))
        return {"ok": False, "rows": rows, "wheel": wheel["filename"]}
    good, log = False, None
    for bundle in prov.get("attestation_bundles", []):
        pub = bundle.get("publisher") or {}
        if pub.get("kind") != "GitHub" or pub.get("repository") != REPOSITORY or pub.get("workflow") != WORKFLOW:
            continue
        for att in bundle.get("attestations", []):
            try:
                statement = json.loads(base64.b64decode(att["envelope"]["statement"]))
            except (KeyError, ValueError):
                continue
            if any(s.get("name") == wheel["filename"] and (s.get("digest") or {}).get("sha256") == digest for s in statement.get("subject", [])):
                good = True
                entries = (att.get("verification_material") or {}).get("transparency_entries") or [{}]
                log = entries[0].get("logIndex")
    rows.append((good, f"PyPI holds a provenance attestation from GitHub {REPOSITORY} ({WORKFLOW}) for this wheel"
                 + (f", Sigstore log index {log}" if good and log is not None else "") if good
                 else f"no attestation from GitHub {REPOSITORY} ({WORKFLOW}) names this wheel's hash"))
    return {"ok": all(ok for ok, _ in rows), "rows": rows, "wheel": wheel["filename"]}
