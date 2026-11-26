"""Add verified published addon releases to the local registry source index."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
from tempfile import NamedTemporaryFile

from validate_index import CATALOG, HEX, INDEX_LIMIT, TARGET, is_transferred_asset, matches, parse, require, validate, version_tuple
from verify_releases import verify_releases

ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
VERSION = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"


def github(path):
    return parse(subprocess.check_output(["gh", "api", "--method", "GET", path]), INDEX_LIMIT)


def public_key(repository, tag):
    response = github(f"repos/{repository}/contents/release-public-key.pem?ref={tag}")
    require(response["encoding"] == "base64", "expected base64-encoded public key file")
    pem = base64.b64decode("".join(response["content"].split()), validate=True).splitlines()
    require(len(pem) >= 3 and pem[0] == b"-----BEGIN PUBLIC KEY-----"
            and pem[-1] == b"-----END PUBLIC KEY-----", "invalid public key PEM")
    key = base64.b64decode(b"".join(pem[1:-1]), validate=True)
    require(key.startswith(ED25519_SPKI) and len(key) == len(ED25519_SPKI) + 32,
            "expected a 32-byte Ed25519 public key")
    return key[len(ED25519_SPKI):].hex()


def published_version(addon_id, version):
    repository, pinned_key, _ = CATALOG[addon_id]
    tag = f"v{version}"
    release = github(f"repos{repository}/releases/tags/{tag}")
    require(release["tag_name"] == tag and release["draft"] is False
            and release["prerelease"] is False, f"{addon_id} {tag} is not a published release")
    key = public_key(repository[1:], tag)
    require(key == pinned_key, f"{addon_id} {tag} public key differs from the catalog")
    archives = [asset for asset in release["assets"] if asset["name"].endswith("-windows-x64.zip")]
    require(len(archives) == 1, f"{addon_id} {tag} must have one Windows x64 ZIP")
    asset = archives[0]
    digest = asset.get("digest") or ""
    matches(digest, "sha256:" + HEX, "GitHub asset digest")
    entry = {
        "version": version, "api": "goodtype-api 0.1", "target": TARGET,
        "url": asset["browser_download_url"], "size": asset["size"], "sha256": digest[7:],
    }
    addon = {"id": addon_id, "repository": repository, "publicKey": key, "versions": [entry]}
    return addon, entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("releases", nargs="+", metavar="ADDON=VERSION")
    parser.add_argument("--min-goodtype", help="Explicit minimum for requested releases; may only raise the computed minimum")
    args = parser.parse_args()
    if args.min_goodtype:
        matches(args.min_goodtype, VERSION, "minimum Goodtype version", 32)
    requested = []
    for spec in args.releases:
        addon_id, _, version = spec.partition("=")
        require(addon_id in CATALOG, f"unknown addon: {addon_id}")
        matches(version, VERSION, "release version", 32)
        require((addon_id, version) not in requested, f"duplicate argument: {spec}")
        requested.append((addon_id, version))

    path = Path(__file__).resolve().parents[1] / "index.json"
    index = validate(path.read_bytes())
    addons = {addon["id"]: addon for addon in index["addons"]}
    for addon_id, version in requested:
        published, entry = published_version(addon_id, version)
        verify_releases({"addons": [published]}, populate=True)
        if args.min_goodtype:
            require(version_tuple(args.min_goodtype) >= version_tuple(entry.get("minGoodtype", "0.0.0")),
                    "override cannot lower the feature minimum")
            entry["minGoodtype"] = args.min_goodtype
        if addon_id not in addons:
            addons[addon_id] = {**published, "versions": []}
            index["addons"].append(addons[addon_id])
        versions = addons[addon_id]["versions"]
        existing = next((item for item in versions if item["version"] == version), None)
        require(existing is None or existing == entry, f"{addon_id} {version} already has different metadata")
        if existing is None:
            versions.append(entry)
        addons[addon_id]["versions"] = [
            item for item in versions if not is_transferred_asset(addon_id, item)
        ]

    data = (json.dumps(index, indent=2) + "\n").encode("utf-8")
    validate(data)
    with NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temp_path = Path(temporary.name)
    try:
        temp_path.write_bytes(data)
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)
    print(f"Updated {path}")


if __name__ == "__main__":
    main()

