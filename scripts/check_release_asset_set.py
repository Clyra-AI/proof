#!/usr/bin/env python3
"""Validate a release asset set and compare downloaded bytes with API digests."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import NoReturn


PLATFORMS = (
    ("darwin_amd64", "tar.gz"),
    ("darwin_arm64", "tar.gz"),
    ("linux_amd64", "tar.gz"),
    ("linux_arm64", "tar.gz"),
    ("windows_amd64", "zip"),
    ("windows_arm64", "zip"),
)
SIGNATURE_ASSETS = frozenset(("checksums.txt.sig", "checksums.txt.pem"))


def expected_assets(version: str) -> set[str]:
    return {
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "sbom.spdx.json",
        *{
            f"proof_{version}_{platform}.{extension}"
            for platform, extension in PLATFORMS
        },
    }


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_json")
    parser.add_argument("dist_dir")
    parser.add_argument("version")
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="allow missing expected assets while rejecting extras and partial signatures",
    )
    parser.add_argument("--missing-output")
    args = parser.parse_args()

    release_json = Path(args.release_json)
    dist_dir = Path(args.dist_dir)
    if not release_json.is_file() or release_json.is_symlink():
        fail(f"release JSON is not a regular file: {release_json}")
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        fail(f"distribution directory is not a real directory: {dist_dir}")

    try:
        data = json.loads(release_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid release JSON: {exc}")
    assets = data.get("assets")
    if not isinstance(assets, list):
        fail("release JSON assets must be an array")

    expected = expected_assets(args.version)
    by_name: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release asset entries must contain string names")
        name = asset["name"]
        if name in by_name:
            fail(f"duplicate release asset: {name}")
        by_name[name] = asset

    actual = set(by_name)
    unexpected = sorted(actual - expected)
    if unexpected:
        fail(f"unexpected release assets: {unexpected}")

    missing = sorted(expected - actual)
    missing_signatures = SIGNATURE_ASSETS & set(missing)
    if missing_signatures and missing_signatures != SIGNATURE_ASSETS:
        fail("release has a partial checksum signature pair")
    if missing and not args.allow_missing:
        fail(f"release is missing expected assets: {missing}")

    dist_root = dist_dir.resolve()
    for name, asset in sorted(by_name.items()):
        digest = asset.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            fail(f"release asset digest missing or unsupported for {name}")
        expected_digest = digest.removeprefix("sha256:")
        if len(expected_digest) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in expected_digest
        ):
            fail(f"release asset digest malformed for {name}")

        path = dist_dir / name
        try:
            path_stat = path.lstat()
        except OSError as exc:
            fail(f"missing downloaded asset {name}: {exc}")
        if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
            fail(f"downloaded asset is not a regular non-symlink file: {name}")
        if path.resolve().parent != dist_root:
            fail(f"downloaded asset escapes distribution directory: {name}")
        actual_digest = sha256(path)
        if actual_digest.lower() != expected_digest.lower():
            fail(f"release asset digest mismatch for {name}: {actual_digest} != {digest}")

    if args.missing_output:
        missing_path = Path(args.missing_output)
        if missing_path.exists() or missing_path.is_symlink():
            fail(f"missing-assets output already exists: {missing_path}")
        missing_path.write_text("".join(f"{name}\n" for name in missing), encoding="utf-8")

    print(f"release asset set verified ({len(actual)} present, {len(missing)} missing)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
