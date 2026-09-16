<p align="center">
  <img src="./media/logo.jpg" alt="ohu logo" width="480">
</p>

# 🔐 ohu

**A fast, algorithm-agnostic CLI for hashing, verification, and encryption — built in Rust.**

![License](https://img.shields.io/badge/license-MIT-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Rust](https://img.shields.io/badge/rust-stable-orange)

---

## ✨ Key Features

- 🔑 **Password hashing** — Argon2, bcrypt
- 🧬 **Digests** — MD5, BLAKE3, xxHash3, SHA-2 (224/256/384/512), SHA-3 (224/256/384/512)
- 🔒 **Authenticated encryption** — AES-128/256-GCM, AES-128/256-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305
- 📄 **File integrity verification** — check any file's hash against an expected value
- ⚖️ **File comparison** — diff two files by content hash instead of byte-by-byte
- 🧩 **One CLI, one interface** — every algorithm behind the same `hash` / `verify` / `encrypt` / `decrypt` commands

---

## 🚀 Quick Start

```bash
git clone https://github.com/ammardevz/ohu.git
cd ohu
cargo build --release
```

Binary lands at `target/release/ohu`. Add it to your `PATH`, or run it directly:

```bash
./target/release/ohu hash --algorithm blake3 "hello world"
```

---

## 📖 Usage

**Hash a string:**

```bash
ohu hash --algorithm argon2 "my-password"
```

**Verify a string against a hash:**

```bash
ohu verify --algorithm argon2 "my-password" "$2b$12$..."
```

**Encrypt a file's contents:**

```bash
ohu encrypt --algorithm aes256-gcm --key <hex-key> "secret data" out.bin
```

**Decrypt it back:**

```bash
ohu decrypt --algorithm aes256-gcm --key <hex-key> out.bin recovered.txt
```

**Verify a file wasn't tampered with:**

```bash
ohu verify-file-integrity --algorithm sha256 downloaded-file.zip <expected-hash>
```

**Compare two files by content:**

```bash
ohu compare-file file-a.txt file-b.txt
```

---

## 🏗️ How It Works

```
CLI (clap)
   │
   ├── Command::Hash / Verify        →  hash::{argon2, bcrypt, md5, blake3, xxhash, sha}
   ├── Command::Encrypt / Decrypt    →  hash::{aes, chacha}
   └── Command::VerifyFileIntegrity  →  hash::* (reads file bytes, delegates to verify_*)
```

Each algorithm lives in its own module under `hash/`, exposing a consistent `hash_*` / `verify_*` (or `encrypt_*` / `decrypt_*`) function pair. The CLI layer just dispatches on the `--algorithm` flag — adding a new algorithm means adding a module and a match arm, nothing else changes.

Encrypted output is nonce-prefixed: the nonce is generated randomly per call, written ahead of the ciphertext, and stripped back off on decrypt — no separate nonce management required.

---

## ⚙️ Configuration

| Flag                 | Applies to                                                      | Description                                                              |
| -------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `--algorithm` / `-a` | `hash`, `verify`, `encrypt`, `decrypt`, `verify-file-integrity` | Selects the algorithm                                                    |
| `--key` / `-k`       | `encrypt`, `decrypt`                                            | Hex-encoded key (16 bytes for AES-128, 32 for AES-256 / ChaCha variants) |
| `--verbose` / `-v`   | global                                                          | Verbose output                                                           |

### 🗺️ Roadmap

- [ ] Streaming support for large files (avoid loading full file into memory)
- [ ] Binary-safe hashing (currently string/UTF-8 only for some algorithms)
- [ ] Config file for default algorithm/key paths
- [ ] Merge `verify-file-integrity` and `compare-file` into a shared path

---

## 🤝 Contributing

PRs welcome. Please:

1. Fork the repo and create a feature branch
2. Follow the existing module pattern (`hash_*` / `verify_*` per algorithm)
3. Run `cargo fmt` and `cargo clippy` before submitting
4. Open a PR with a clear description of the change

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
