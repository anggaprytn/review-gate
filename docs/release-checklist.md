# Release Checklist

Run these checks before tagging a release:

```bash
cargo fmt --all -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
./target/release/reviewgate --version
./target/release/reviewgate doctor
git diff --check
git ls-files docs/PRD.md
```

Expected:

- `docs/PRD.md` is not tracked.
- `.env` is not tracked.
- `.reviewgate/` is not tracked.
