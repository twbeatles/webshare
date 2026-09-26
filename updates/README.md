# WebShare Pro Update Channel

This directory publishes the public release manifest for WebShare Pro automatic updates.

## Current Production Release: `v7.3.0`

- `latest.json`: The signed metadata file for the latest release on the primary channel.
- Signature verification: Validated using the embedded Ed25519 public key.
- Bundled with: High-performance Go native core engine (`webshare-core.exe`) and Python fallback.
- Never commit private signing keys to this repository.

## Release Process & Manifest Verification

1. When a new tag `v*` is pushed to GitHub, `.github/workflows/release.yml` triggers.
2. The workflow compiles the Go core binary (`go-core/webshare-core.exe`), runs verification tests (`go test ./...` and `pytest`), packages `dist/WebSharePro-v*.exe` via PyInstaller, and executes a headless smoke test (`--smoke`).
3. The release workflow signs the manifest payload using the repository secret `WEBSHARE_UPDATE_PRIVATE_KEY_B64` and publishes both the EXE asset and `latest.json` to the GitHub Release.
4. The workflow automatically pushes the updated `latest.json` to the `main` branch.
