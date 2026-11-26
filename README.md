# Goodtype Addons

This is the first-party registry for Windows x64 Goodtype addons. Goodtype accepts only IDs in its built-in catalog and rejects repository and release-key mismatches. Adding an addon identity or rotating a key requires a Goodtype release with the corresponding catalog entry.

## Add a release

Publish the addon ZIP and its signed update descriptor in the addon's own GitHub repository. Open a pull request against `main` with the version, API, target, GitHub release URL, byte size, and SHA-256 in `index.json`. Validation downloads the ZIP, verifies the descriptor against the catalog key, and checks the package manifest. The two exact legacy importer archives use Goodtype's built-in compatibility manifests.

After publication, run `python scripts/add_releases.py ADDON=VERSION [ADDON=VERSION ...]` from this checkout. It reads releases and tagged public keys through the authenticated GitHub CLI, verifies the assets, and updates the local source index in one write. The three indexed archives from before the transfer keep their signed URLs and exact hashes until their replacements are added. The publisher keeps the last published snapshot until all three entries have been replaced by org releases.

Run `python scripts/validate_index.py --self-test --network` from the repository root with Python 3.11 or later and OpenSSL on your PATH. The format check uses Python; the offline self-test also uses OpenSSL with an ephemeral test key. The [format 1 schema](addon-index-v1.schema.json) documents the on-wire fields.

## Publishing and trust

The publisher assigns the next sequence from the latest verified release, sets issuance and 120-day expiry timestamps, and signs the exact UTF-8 bytes with Ed25519. Keep the publication metadata in the source index as a template. Pushes to main, monthly runs, and manual dispatches all use the same publisher. The repository's Actions secret holds the signing key and `registry-public-key.txt` holds the public key.

Goodtype verifies the signature before parsing, rejects expired snapshots, and rejects sequences below the highest sequence it has accepted. Installed addons remain usable when an index expires or an update check fails. Install verification also checks the downloaded archive and its independently signed descriptor.

Download the current [index.json](https://github.com/goodtype-notes/Goodtype-Addons/releases/latest/download/index.json) and [index.json.sig](https://github.com/goodtype-notes/Goodtype-Addons/releases/latest/download/index.json.sig). Save them side by side and run `python scripts/sign_index.py --verify index.json` to verify the signature and structure.

## Registry format 2

`index.json` in this checkout is the single format-2 source template, documented by
[the format-2 schema](addon-index-v2.schema.json). Publication generates both
`index.json` (format 1) and `index-v2.json` (format 2), with detached `.sig` files,
in one GitHub release. Both use the same key, sequence, issuance and expiry.
The format-1 asset retains its strict original shape. It excludes releases with
nonempty `requires` or any `minGoodtype`, and omits addons left with no versions.
The format-2 asset includes every release and permits optional `requires` and
`minGoodtype` fields alongside the existing version, api, target, url, size and sha256.

[feature-versions.json](feature-versions.json) maps features to the first Goodtype
version that shipped them: `end-caps`, `group-stretch` and `path-edit-v0` currently
all require `0.3.10`. `add_releases.py` reads requirements from the verified package
manifest and computes the highest required version. Unknown features are rejected
until the table is updated. `--min-goodtype X.Y.Z` optionally raises the minimum
for the requested releases; it cannot lower it. Network validation checks that
source requirements match the verified manifest and that the minimum is sufficient.
Requirement-bearing versions can now be indexed as soon as they are tagged,
because old hosts never see them. Manifests do not gain a minimum-version field.

Verify downloaded format 2 with `python scripts/sign_index.py --verify index-v2.json`.
Hosts try format 2 first and fall back only when it is missing, never after a bad signature.
