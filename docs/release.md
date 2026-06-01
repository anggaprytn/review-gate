# Release

ReviewGate release builds are created from Git tags that match `v*`.

```bash
git tag v0.1.0-alpha
git push origin v0.1.0-alpha
```

The release workflow builds compressed binary archives for:

- Linux x86_64
- macOS arm64

The workflow publishes GitHub Release assets named with the tag and target triple:

```text
reviewgate-v0.1.0-alpha-aarch64-apple-darwin.tar.gz
reviewgate-v0.1.0-alpha-x86_64-unknown-linux-gnu.tar.gz
checksums.txt
```

The install script downloads `reviewgate-<version>-<target>.tar.gz` and verifies it with `checksums.txt`.

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
