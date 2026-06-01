# Release Smoke Test

Use this checklist after publishing a GitHub Release to verify a new user can install and run ReviewGate without a source checkout.

## Fresh Install

```bash
mkdir -p /tmp/reviewgate-smoke
cd /tmp/reviewgate-smoke
curl -fsSL https://raw.githubusercontent.com/Anggaprytn/review-gate/main/scripts/install.sh | sh
reviewgate --version
reviewgate doctor
```

To test a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/Anggaprytn/review-gate/main/scripts/install.sh | REVIEWGATE_VERSION=v0.1.0-alpha sh
```

## Review Flow

Set `MR_URL` to a merge request that is safe to test.

```bash
reviewgate --version
reviewgate doctor
reviewgate review "$MR_URL" --dry-run
reviewgate review "$MR_URL" --preview
reviewgate review "$MR_URL" --publish
reviewgate verify "$MR_URL" --preview
```

`reviewgate review "$MR_URL" --publish` should publish a summary note only.

Do not repeatedly spam-test `--publish-inline` on a public merge request. Use a disposable merge request for inline publishing tests.
