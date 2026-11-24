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
        "/goodtype-notes/Goodtype-Goodnotes-Importer",
        "428cc68f6d0b38eae74dcb211e4877c6eb51548daabf24de64a185885c825b3c",
        "ef8bfd150626eab885cf1479131e5945fcfd2a9da4152aab3a03311507db5742",
    ),
    "onenote": (
        "/goodtype-notes/Goodtype-OneNote-Importer",
        "73bce698801a59fe2d423fd9c6dba8687fe3b92f60bb9f27499e7242c2336c3b",
        "a09f7899eef1280819a7da0b12e1355a76e2a71c774e738b0945e07bac9a63dc",
    ),
    "math": (
        "/goodtype-notes/Goodtype-Math-Recognition",
        "c9beeeed664e245b76771380ed37b66c9405d445e2880af9356d13a384955581",
        None,
    ),
    "connectors": (
        "/goodtype-notes/Goodtype-Connectors",
        "210597a7b6ad9c6d9ceb5144d8efdff2a1b387352ae2f70791924a437fdfb4b7",
        None,
    ),
    "engineering-shapes": (
        "/goodtype-notes/Goodtype-Engineering-Shapes",
        "3cfbfe38cee6bbc1da2c63caff5b8ef1f0f76db6df0c1c0f1763728781b782d9",
        None,
    ),
    "study-templates": (
        "/goodtype-notes/Goodtype-Study-Templates",
        "3c7b9d349406055325ee05156505328d763e3c684cdbc36d1c361a59c92a7acd",
        None,
    ),
}

# The signed descriptors and source entries for these three immutable assets predate the transfer.
TRANSFERRED_ASSETS = {
    "goodnotes": (
        "https://github.com/Just8it/Goodtype-Goodnodes-importer/releases/download/v0.1.1/goodtype-goodnotes-importer-0.1.1-windows-x64.zip",
        14881982,
        "ef8bfd150626eab885cf1479131e5945fcfd2a9da4152aab3a03311507db5742",
    ),
    "onenote": (
        "https://github.com/Just8it/Goodtype-OneNote-Importer/releases/download/v0.1.0/goodtype-onenote-importer-0.1.0-windows-x64.zip",
        1927930,
        "a09f7899eef1280819a7da0b12e1355a76e2a71c774e738b0945e07bac9a63dc",
    ),
    "math": (
        "https://github.com/Just8it/Goodtype-ink-recognition/releases/download/v0.1.0/goodtype-math-recognizer-0.1.0-windows-x64.zip",
        337200465,
        "415bc6a86c6e1340d0a04b7876cdaca9089cbcaa9ceefd899c08386043d02e38",
    ),
}
CONTENT_PACKS = {"engineering-shapes", "study-templates"}
RECOGNIZERS = {"math"}


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


def is_transferred_asset(addon_id, release):
    expected = TRANSFERRED_ASSETS.get(addon_id)
    return expected == (release["url"], release["size"], release["sha256"]) and (
        f"/download/v{release['version']}/" in release["url"]
    )


def validate(data, previous=None, *, historical=False):
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
        canonical = CATALOG[addon_id][0]
        old_asset = TRANSFERRED_ASSETS.get(addon_id)
        old_repository = old_asset[0].removeprefix("https://github.com").split("/releases/", 1)[0] if old_asset else None
        old_snapshot = historical and old_repository is not None and repository == old_repository
        require(repository == canonical or old_snapshot, f"catalog repository mismatch: {addon_id}")
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
            transferred = is_transferred_asset(addon_id, release)
            require(not old_snapshot or transferred, "unexpected archive in a pre-transfer snapshot")
            if not transferred:
                matches(release["url"], prefix + "v" + re.escape(version) + "/" + segment, "release URL")
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
        (release, "url", release["url"].replace("https://github.com/", "https://github.com/foreign/")),
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
