"""Validate index format 1 and, with --network, verify the listed releases."""
import argparse
import copy
from datetime import datetime
import json
from pathlib import Path
import re

INDEX_LIMIT = 1024 * 1024
ARCHIVE_LIMIT = 512 * INDEX_LIMIT
MAX_SEQUENCE = 2**53 - 1
ID = r"[a-z0-9]+(?:-[a-z0-9]+)*"
HEX = r"[0-9a-fA-F]{64}"
TARGET = "x86_64-pc-windows-msvc"
CATALOG = {
    "goodnotes": (
        "/Just8it/Goodtype-Goodnodes-importer",
        "428cc68f6d0b38eae74dcb211e4877c6eb51548daabf24de64a185885c825b3c",
        "ef8bfd150626eab885cf1479131e5945fcfd2a9da4152aab3a03311507db5742",
    ),
    "onenote": (
        "/Just8it/Goodtype-OneNote-Importer",
        "73bce698801a59fe2d423fd9c6dba8687fe3b92f60bb9f27499e7242c2336c3b",
        "a09f7899eef1280819a7da0b12e1355a76e2a71c774e738b0945e07bac9a63dc",
    ),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def parse(data, limit=INDEX_LIMIT):
    require(len(data) <= limit, "JSON exceeds its byte limit")
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def fields(value, names):
    require(type(value) is dict and value.keys() == set(names.split()),
            f"expected exactly these fields: {names}")


def matches(value, pattern, name, limit=None):
    require(type(value) is str and (limit is None or len(value) <= limit)
            and re.fullmatch(pattern, value), f"invalid {name}")


def timestamp(value):
    matches(value, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", "UTC timestamp")
    moment = datetime.fromisoformat(value)
    # Keep fractional precision beyond datetime's microseconds for comparisons.
    fraction = value[20:-1].rstrip("0") if value[19] == "." else ""
    return moment.replace(microsecond=0), fraction


def validate(data, previous=None):
    index = parse(data)
    fields(index, "format sequence issued expires addons")
    require(type(index["format"]) is int and index["format"] == 1, "invalid format")
    sequence = index["sequence"]
    require(type(sequence) is int and 0 <= sequence <= MAX_SEQUENCE, "invalid sequence")
    require(previous is None or sequence > previous, "sequence must increase")
    require(timestamp(index["expires"]) > timestamp(index["issued"]), "expires must follow issued")
    require(type(index["addons"]) is list, "addons must be an array")
    ids = set()
    for addon in index["addons"]:
        fields(addon, "id repository publicKey versions")
        addon_id = addon["id"]
        matches(addon_id, ID, "addon id", 48)
        require(addon_id not in ids, f"duplicate addon id: {addon_id}")
        ids.add(addon_id)
        require(addon_id in CATALOG, f"unknown catalog id: {addon_id}")
        repository = addon["repository"]
        require(repository == CATALOG[addon_id][0], f"catalog repository mismatch: {addon_id}")
        matches(addon["publicKey"], HEX, "publicKey")
        require(addon["publicKey"].lower() == CATALOG[addon_id][1], f"catalog key mismatch: {addon_id}")
        require(type(addon["versions"]) is list, "versions must be an array")
        versions = set()
        for release in addon["versions"]:
            fields(release, "version api target url size sha256")
            version = release["version"]
            matches(version, r"[0-9]+\.[0-9]+\.[0-9]+", "version", 32)
            require(version not in versions, f"duplicate version: {addon_id} {version}")
            versions.add(version)
            matches(release["api"], r"goodtype-api 0\.[0-9]+", "api")
            require(release["target"] == TARGET, "invalid target")
            # Reject encoded separators and dot segments before making any request.
            segment = r"(?!\.{1,2}(?:/|$))[A-Za-z0-9._+-]+"
            prefix = re.escape(f"https://github.com{repository}/releases/download/")
            matches(release["url"], prefix + segment + "/" + segment, "release URL")
            require(type(release["size"]) is int and 1 <= release["size"] <= ARCHIVE_LIMIT,
                    "invalid archive size")
            matches(release["sha256"], HEX, "sha256")
    return index


def self_test(data):
    index = validate(data)
    addon = index["addons"][0]
    release = addon["versions"][0]
    invalid = [data.replace(b'"format"', b'"format": 1, "format"', 1)]
    for obj, key, value in [
        (release, "sha256", "z" * 64),
        (release, "url", release["url"].replace(addon["repository"], "/foreign/repo")),
        (addon, "publicKey", "0" * 64),
        (index, "unknown", True),
    ]:
        original = copy.copy(obj)
        obj[key] = value
        invalid.append(json.dumps(index).encode())
        obj.clear()
        obj.update(original)
    for fixture in invalid:
        try:
            validate(fixture)
        except ValueError:
            continue
        raise ValueError("invalid fixture was accepted")
    try:
        validate(data, previous=index["sequence"])
    except ValueError:
        pass
    else:
        raise ValueError("unchanged published sequence was accepted")
    print("Negative fixtures passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path, nargs="?", default=Path("index.json"))
    parser.add_argument("--previous", type=Path, help="Compare two published indexes")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    data = args.index.read_bytes()
    previous = validate(args.previous.read_bytes())["sequence"] if args.previous else None
    index = validate(data, previous)
    if args.self_test:
        self_test(data)
    if args.network:
        from verify_releases import verify_releases
        verify_releases(index)
    print(f"Valid index (sequence {index['sequence']})")


if __name__ == "__main__":
    main()
