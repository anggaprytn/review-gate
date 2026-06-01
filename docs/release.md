# Release

ReviewGate release builds are created from Git tags that match `v*`.

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds compressed binary archives and checksum files for:

- Linux x86_64
- macOS arm64

The workflow uploads artifacts only. It does not automatically publish a GitHub Release.

## Local Release Build

```bash
cargo fmt --all -- --check
cargo check
cargo test
cargo build --release
./target/release/reviewgate --version
```

The release binary is:

```text
target/release/reviewgate
```
