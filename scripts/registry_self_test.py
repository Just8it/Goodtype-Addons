"""Offline dual-publication regression checks using an ephemeral signing key."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

from validate_index import encode, minimum_version, outputs, require, validate


def run(source):
    from sign_index import sign
    from verify_releases import verify_manifest
    import io
    import json
    import zipfile

    fixture = copy.deepcopy(source)
    fixture["format"] = 2
    addon = fixture["addons"][0]
    release = addon["versions"][0]
    release["requires"] = ["end-caps", "group-stretch", "path-edit-v0"]
    release["minGoodtype"] = minimum_version(release["requires"])
    require(release["minGoodtype"] == "0.3.10", "incorrect feature minimum")
    legacy, modern = outputs(fixture)
    require(all(a["id"] != addon["id"] for a in legacy["addons"]), "requirement-only addon leaked")
    require(all("requires" not in r and "minGoodtype" not in r
                for a in legacy["addons"] for r in a["versions"]), "new fields leaked")
    require(modern == fixture, "format 2 lost releases")
    for features in (["future-feature"], ["end-caps", "end-caps"], ["bad_feature"], ["end-caps"] * 17):
        try:
            minimum_version(features)
        except ValueError:
            pass
        else:
            raise ValueError("invalid requirements accepted")
    for minimum in ("0.3.9", "0.3.10-beta"):
        bad = copy.deepcopy(fixture)
        bad["addons"][0]["versions"][0]["minGoodtype"] = minimum
        try:
            validate(encode(bad))
        except ValueError:
            pass
        else:
            raise ValueError("invalid minimum accepted")
    release["minGoodtype"] = "0.4.0"
    validate(encode(fixture))
    # Exercise verified-manifest requirement extraction and mismatch rejection.
    pack = next(a for a in source["addons"] if a["id"] == "engineering-shapes")
    entry = copy.deepcopy(pack["versions"][0])
    root = entry["url"].rsplit("/", 1)[1].removesuffix(".zip") + "/"
    manifest = dict(manifestVersion=1, id=pack["id"], version=entry["version"],
                    apiVersion=entry["api"], target=entry["target"], transport="content",
                    permissions=[], requires=["end-caps"])
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(root + "goodtype-addon.json", json.dumps(manifest))
    verify_manifest(archive, pack, entry, False, populate=True)
    require(entry["requires"] == ["end-caps"] and entry["minGoodtype"] == "0.3.10",
            "manifest extraction failed")
    entry.pop("requires")
    try:
        verify_manifest(archive, pack, entry, False)
    except ValueError:
        pass
    else:
        raise ValueError("manifest mismatch accepted")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        key = directory / "key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
        public = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"])[-32:].hex()
        with patch.dict(os.environ, {"REGISTRY_SIGNING_KEY": key.read_text()}):
            for name, index in zip(("index.json", "index-v2.json"), outputs(fixture)):
                path = directory / name
                path.write_bytes(encode(index))
                sign(path, public)  # sign() verifies each exact-byte signature.
