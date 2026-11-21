"""Prepare the next registry index and sign its exact UTF-8 bytes with OpenSSL."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from validate_index import INDEX_LIMIT, parse, require, validate
from verify_releases import download, verify_signature

REPO = "Just8it/Goodtype-Addons"
PUBLIC_KEY = Path(__file__).resolve().parents[1] / "registry-public-key.txt"


def github_api(path):
    headers = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(f"https://api.github.com/repos/{REPO}/{path}", headers=headers),
                 timeout=30) as response:
        return parse(response.read(INDEX_LIMIT + 1))


def latest_sequence(public_key):
    try:
        latest = github_api("releases/latest")
    except HTTPError as error:
        if error.code != 404:
            raise
        releases = github_api("releases?per_page=1")
        require(releases == [], "registry has releases but no latest release")
        return 0

    tag = latest["tag_name"]
    require(re.fullmatch(r"index-[1-9][0-9]*", tag), "unexpected latest release tag")
    url = f"https://github.com/{REPO}/releases/download/{tag}/index.json"
    data = download(url, INDEX_LIMIT)
    verify_signature(data, download(url + ".sig", 64), public_key)
    index = validate(data)
    require(tag == f"index-{index['sequence']}", "latest tag and sequence disagree")
    return index["sequence"]


def prepare(source, previous):
    index = validate(source)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    index.update(sequence=previous + 1, issued=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                 expires=(now + timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    data = (json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    validate(data, previous)
    return data


def sign(index_file, public_key):
    with tempfile.TemporaryDirectory(prefix="goodtype-registry-sign-") as temporary:
        secret = Path(temporary) / "key.pem"
        signature = Path(temporary) / "index.json.sig"
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(os.environ["REGISTRY_SIGNING_KEY"])
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(secret),
                        "-in", str(index_file), "-out", str(signature)], check=True)
        data = signature.read_bytes()
        verify_signature(index_file.read_bytes(), data, public_key)
        index_file.with_suffix(".json.sig").write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("index.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--verify", type=Path, metavar="INDEX")
    args = parser.parse_args()
    public_key = PUBLIC_KEY.read_text(encoding="ascii").strip()
    if args.verify:
        data = args.verify.read_bytes()
        require(len(data) <= INDEX_LIMIT, "index exceeds byte limit")
        verify_signature(data, args.verify.with_suffix(".json.sig").read_bytes(), public_key)
        index = validate(data)
        print(f"Verified registry signature (sequence {index['sequence']})")
        return

    data = prepare(args.source.read_bytes(), latest_sequence(public_key))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    index_file = args.output_dir / "index.json"
    index_file.write_bytes(data)
    if not args.prepare_only:
        sign(index_file, public_key)
    print(f"Prepared registry index {validate(data)['sequence']}")


if __name__ == "__main__":
    main()
