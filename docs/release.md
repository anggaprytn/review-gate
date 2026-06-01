# Release

ReviewGate release builds are created from Git tags that match `v*`.

```bash
git tag v0.1.0-alpha.2
git push origin v0.1.0-alpha.2
```

The release workflow builds compressed binary archives for:

- Linux x86_64
- macOS arm64

The workflow publishes GitHub Release assets named with the tag and target triple:

```text
reviewgate-v0.1.0-alpha.2-aarch64-apple-darwin.tar.gz
reviewgate-v0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz
checksums.txt
```

The install script downloads `reviewgate-<version>-<target>.tar.gz` and verifies it with `checksums.txt`.

Default install:

```bash
curl -fsSL https://raw.githubusercontent.com/anggaprytn/review-gate/main/scripts/install.sh | sh
reviewgate doctor
```

The default installer resolves GitHub's latest release URL. Keep alpha releases as normal GitHub Releases, not prereleases, until the install script explicitly supports prerelease latest resolution.

To install a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/anggaprytn/review-gate/main/scripts/install.sh | REVIEWGATE_VERSION=v0.1.0-alpha.2 sh
```

## Local Release Build

```bash
cargo fmt --all -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
./target/release/reviewgate --version
./target/release/reviewgate doctor
```

The release binary is:

```text
target/release/reviewgate
```
