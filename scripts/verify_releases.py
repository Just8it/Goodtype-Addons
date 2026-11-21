"""Verify published GitHub assets without extracting untrusted ZIP files."""
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener
import zipfile

from validate_index import (
    ARCHIVE_LIMIT, CATALOG, ID, INDEX_LIMIT, fields, matches, parse, require,
)

ASSET_HOSTS = {
    "objects.githubusercontent.com", "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
MANIFEST_LIMIT = 64 * 1024


class AssetRedirects(HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlsplit(newurl)
        require(url.scheme == "https" and url.netloc in ASSET_HOSTS,
                "unexpected GitHub asset redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit, output=None):
    with build_opener(AssetRedirects()).open(url, timeout=45) as response:
        if output is None:
            data = response.read(limit + 1)
            require(len(data) <= limit, "asset exceeds byte limit")
            return data
        digest = hashlib.sha256()
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            require(size <= limit, "archive exceeds declared size")
            digest.update(chunk)
            output.write(chunk)
        return size, digest.hexdigest()


def verify_signature(data, signature, public_key):
    require(len(signature) == 64, "invalid Ed25519 signature length")
    matches(public_key, r"[0-9a-fA-F]{64}", "Ed25519 public key")
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        index_file = directory / "data"
        sig_file = directory / "data.sig"
        key_file = directory / "key.der"
        index_file.write_bytes(data)
        sig_file.write_bytes(signature)
        # RFC 8410 SubjectPublicKeyInfo prefix followed by the raw key.
        key_file.write_bytes(bytes.fromhex("302a300506032b6570032100" + public_key))
        subprocess.run([
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
            "-inkey", str(key_file), "-in", str(index_file), "-sigfile", str(sig_file),
        ], check=True, stdout=subprocess.DEVNULL)


def verify_descriptor(addon, release, legacy):
    base, filename = release["url"].rsplit("/", 1)
    descriptor_url = f"{base}/importer-update.json"
    try:
        data = download(descriptor_url, MANIFEST_LIMIT)
    except HTTPError as error:
        if error.code != 404 or not legacy:
            raise
        try:
            download(descriptor_url + ".sig", 64)
        except HTTPError as sig_error:
            if sig_error.code != 404:
                raise
            print(f"{addon['id']} {release['version']}: legacy descriptor absent")
            return
        raise ValueError("descriptor signature exists without descriptor") from error

    verify_signature(data, download(descriptor_url + ".sig", 64), addon["publicKey"])
    descriptor = parse(data, MANIFEST_LIMIT)
    archive = descriptor["archive"]
    require(descriptor["version"] == release["version"]
            and descriptor["target"] == release["target"]
            and descriptor["sourceDirty"] is False
            and archive["fileName"] == filename
            and type(archive["sizeBytes"]) is int and archive["sizeBytes"] == release["size"]
            and archive["sha256"].lower() == release["sha256"].lower()
            and archive["url"] == release["url"], "descriptor does not match indexed release")
    for key in ("sourceCommit", "decoderCommit"):
        matches(descriptor[key], r"[0-9a-fA-F]{40}", key)


def verify_manifest(zip_file, addon, release, legacy):
    addon_id = addon["id"]
    executable = f"goodtype-{addon_id}-import.exe"
    root = f"goodtype-{addon_id}-importer-{release['version']}-windows-x64/"
    with zipfile.ZipFile(zip_file) as archive:
        files = archive.infolist()
        require(len(files) <= 20_000 and sum(f.file_size for f in files) <= ARCHIVE_LIMIT,
                "archive exceeds entry or expanded size limit")
        require(all(f.filename.startswith(root) for f in files), "unexpected archive root")
        manifests = [f for f in files if f.filename == root + "goodtype-addon.json"]
        if not manifests and legacy:
            print(f"{addon_id} {release['version']}: exact legacy archive uses the host manifest")
            return
        require(len(manifests) == 1 and manifests[0].file_size <= MANIFEST_LIMIT,
                "expected one bounded goodtype-addon.json")
        manifest = parse(archive.read(manifests[0]), MANIFEST_LIMIT)
        require(archive.namelist().count(root + executable) == 1, "catalog executable missing")

    fields(manifest, "manifestVersion id version apiVersion target entrypoint transport "
           "permissions commands settings strings")
    require(type(manifest["manifestVersion"]) is int and manifest["manifestVersion"] == 1
            and manifest["id"] == addon_id and manifest["version"] == release["version"]
            and manifest["apiVersion"] == release["api"] == "goodtype-api 0.1"
            and manifest["target"] == release["target"] and manifest["entrypoint"] == executable
            and manifest["transport"] == "legacy-import-cli", "manifest identity mismatch")
    approved = {"picked-import-file", "publish-import-batch"}
    if addon_id == "goodnotes":
        approved.add("derived-import-artwork")
    permissions = manifest["permissions"]
    require(type(permissions) is list and set(permissions) <= approved
            and len(permissions) == len(set(permissions)), "invalid importer permissions")
    require(manifest["settings"] == [], "settings are reserved in API 0.1")
    commands = manifest["commands"]
    require(type(commands) is list and len(commands) == 1, "expected one importer command")
    command = commands[0]
    fields(command, "id label surface")
    require(command["id"] == "import-notebooks" and command["surface"] == "library-import",
            "invalid importer command")
    matches(command["label"], ID, "command label", 48)
    strings = manifest["strings"]
    fields(strings, "en de")
    for table in strings.values():
        require(type(table) is dict and len(table) <= 128
                and {"name", command["label"]} <= table.keys(), "missing or excessive localized strings")
        for key, value in table.items():
            matches(key, ID, "localization key", 48)
            matches(value, r"[^<>\x00-\x1f\x7f-\x9f\ud800-\udfff]{1,256}", "localized text")
            require("{{" not in value and "}}" not in value, "interpolation in localized text")
    require(strings["en"].keys() == strings["de"].keys(), "English and German keys differ")


def verify_releases(index):
    for addon in index["addons"]:
        for release in addon["versions"]:
            expected_hash = release["sha256"].lower()
            legacy = expected_hash == CATALOG[addon["id"]][2]
            with tempfile.TemporaryFile() as archive:
                size, digest = download(release["url"], release["size"], archive)
                require(size == release["size"] and digest == expected_hash,
                        f"archive size or SHA-256 mismatch: {release['url']}")
                verify_descriptor(addon, release, legacy)
                verify_manifest(archive, addon, release, legacy)
            print(f"Verified {addon['id']} {release['version']} release assets")
