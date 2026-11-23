# Goodtype Addons

This is the first-party registry for Windows x64 Goodtype addons. Goodtype accepts only IDs in its built-in catalog and rejects repository and release-key mismatches. Adding an addon identity or rotating a key requires a Goodtype release with the corresponding catalog entry.

## Add a release

Publish the addon ZIP and its signed update descriptor in the addon's own GitHub repository. Open a pull request against `main` with the version, API, target, GitHub release URL, byte size, and SHA-256 in `index.json`. Validation downloads the ZIP, verifies the descriptor against the catalog key, and checks the package manifest. The two exact legacy importer archives use Goodtype's built-in compatibility manifests.

After publication, run `python scripts/add_releases.py ADDON=VERSION [ADDON=VERSION ...]` from this checkout. It reads releases and tagged public keys through the authenticated GitHub CLI, verifies the assets, and updates the local source index in one write. The three indexed archives from before the transfer keep their signed URLs and exact hashes until their replacements are added. The publisher keeps the last published snapshot until all three entries have been replaced by org releases.

Run `python scripts/validate_index.py --self-test --network` from the repository root with Python 3.11 or later and OpenSSL on your PATH. The offline format check needs only Python. The [format 1 schema](addon-index-v1.schema.json) documents the on-wire fields.

## Publishing and trust

The publisher assigns the next sequence from the latest verified release, sets issuance and 120-day expiry timestamps, and signs the exact UTF-8 bytes with Ed25519. Keep the publication metadata in the source index as a template. Pushes to main, monthly runs, and manual dispatches all use the same publisher. The repository's Actions secret holds the signing key and `registry-public-key.txt` holds the public key.

Goodtype verifies the signature before parsing, rejects expired snapshots, and rejects sequences below the highest sequence it has accepted. Installed addons remain usable when an index expires or an update check fails. Install verification also checks the downloaded archive and its independently signed descriptor.

Download the current [index.json](https://github.com/goodtype-notes/Goodtype-Addons/releases/latest/download/index.json) and [index.json.sig](https://github.com/goodtype-notes/Goodtype-Addons/releases/latest/download/index.json.sig). Save them side by side and run `python scripts/sign_index.py --verify index.json` to verify the signature and structure.
