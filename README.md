# Vault — a command-line password manager

**Team Members:** Liu Congwen, Zhou Yi, Wu Siyuan

A small, dependency-light password manager written in Python. It stores your
passwords in a single encrypted file that can only be opened with a master
password that lives in your head — never on disk.

Everything is built from established, audited libraries (`argon2-cffi` and
`cryptography`) plus the Python standard library. **No cryptography is
hand-rolled.**

---

## Quick start

```bash
pip install -r requirements.txt

python vault.py init                     # set the master password (first run)
python vault.py add github --user alice  # store an entry (generates a password)
python vault.py get github               # read it back
python vault.py list                     # list all sites
python vault.py gen --length 20          # generate a strong password
python vault.py delete github            # remove an entry
python vault.py unlock                   # verify the master password
```

Every command that touches the vault prompts for the master password (with
`getpass`, so it is never echoed to the screen). There is no persistent
session: each invocation independently verifies the password, derives the key,
and decrypts the vault. For scripts and automated tests only, you can supply
the password via the `VAULT_PASSWORD` environment variable instead of typing
it interactively.

---

## What the tool protects against

- **The vault file being stolen.** Whoever steals `vault.json` gets only
  AES-256-GCM ciphertext plus an Argon2id hash. Neither reveals the entries
  without the master password. The master password itself never touches disk.

## What it does **not** protect against

The tool is honest about its limits. It does **not** protect against:

- **A keylogger on your machine.** If malware records your keystrokes, it
  captures the master password the moment you type it, and the vault is open.
- **A weak master password.** Argon2id slows brute-force guessing dramatically,
  but it cannot make `password123` strong. An attacker who steals the file can
  still guess a weak master password offline.
- **Your screen being read.** Shoulder-surfing, a compromised camera, or screen
  recording all reveal both the master password and the decrypted entries.
- **Malware running as your user.** Once the vault is unlocked in memory, any
  process with your privileges can read it (including clipboard-sniffing when
  you copy a password).

A password manager that knows its limits is worth more than one that pretends
to be magic.

---

## The four building blocks — and *why*

### 1. Master password verification with Argon2id

We use `argon2-cffi.PasswordHasher` to hash the master password during `init`.
The stored `master_hash` is an `$argon2id$...` string containing the algorithm,
version, cost parameters, salt, and hash. `verify_master()` calls `PH.verify()`
with this string and the entered password. A mismatch is rejected with an error
and exit code 1; the original password is not recovered from the hash.

Argon2id is designed for password hashing: its computation and memory costs make
each offline guess more expensive than a fast general-purpose hash such as
SHA-256. It does not prevent parallel attacks or make weak passwords safe.
AES is reversible encryption, so it does not serve the same purpose as a
password-verification hash.

`PasswordHasher.hash()` generates its own random salt. Repeating the same
password therefore normally produces different encoded hashes. Verification
uses the salt and parameters embedded in the stored hash, rather than comparing
two newly generated hash strings.

The configured profile is `time_cost=3`, `memory_cost=65536` KiB (64 MiB),
`parallelism=4`, and `hash_len=32` bytes. These are this project's chosen settings,
not a claim that Argon2id only supports these values or that they are optimal for
every machine. Higher costs also increase legitimate unlock time; this project
does not include a hardware benchmark.

### 2. Encryption key derived from the master password

`derive_key()` uses `argon2.low_level.hash_secret_raw(..., type=Type.ID)` to derive
a 32-byte (256-bit) AES key from the UTF-8 encoded master password, a salt, and
the stored cost parameters. This raw key is different from the encoded
`master_hash`: the hash verifies the password, while the raw key encrypts and
decrypts entries. `derive_key()` alone does not verify that a password is correct;
`load_and_unlock()` calls `verify_master()` first.

At initialization, `os.urandom(16)` creates a separate KDF salt. It is stored as
`kdf.salt_b64`, independently of the verification salt inside `master_hash`.
A salt is public; Base64 only makes its bytes suitable for JSON and does not
encrypt them. The same password, salt, and parameters reproduce the same key on
each unlock. Changing the password or salt changes the derived key in our tests.
The derived key is used in memory and is not written to a key file.

If an unencrypted key were saved beside the vault, an attacker who copied both
files could decrypt the entries without guessing the master password. Derivation
avoids that extra secret file. It still depends on a strong master password and
does not protect secrets from malware reading the running process.

#### Accepted KDF format

Before invoking Argon2id, `derive_key()` requires a `kdf` object containing all
five fields below:

| Field | Accepted value |
|---|---|
| `salt_b64` | A string accepted by strict Base64 decoding, yielding exactly 16 bytes |
| `time_cost` | Integer `3` |
| `memory_cost` | Integer `65536` (KiB) |
| `parallelism` | Integer `4` |
| `hash_len` | Integer `32` (bytes, for AES-256) |

The numeric fields must be Python integers after JSON loading; booleans,
strings, floats, and null are rejected. Missing fields, invalid salt encoding or
length, and unsupported numeric values produce a specific error and exit code 1.
Strict decoding uses `validate=True`, so invalid characters are not silently
ignored. Validation rejects unsupported resource settings before the KDF runs.

This fixed profile matches vaults generated by the current `init` command.
Other Argon2 configurations, even if valid for the library, are not supported by
this reader. Future changes need an explicit compatibility or migration plan;
existing vault parameters must not be silently rewritten, since doing so changes
the derived key.

These checks apply to the `kdf` object. They do not authenticate all JSON
metadata or bound the work requested by the separate `master_hash` string, which
`PH.verify()` processes before `derive_key()`. They are not complete validation
of every possible vault-file input.

### 3. Vault encrypted with AES-256-GCM — authenticated encryption

The whole entry database (a JSON dict) is encrypted with **AES-256-GCM**
(`cryptography`). GCM is *authenticated encryption with associated data*
(AEAD): it provides **confidentiality** *and* **integrity** in one step.

Why not AES without authentication, like AES-CBC or AES-CTR? Plain AES-CBC/CTR
only hides the data; it gives no way to tell whether the ciphertext was
modified. An attacker who flips a byte in a CBC ciphertext can corrupt a known
field, or trigger a padding-oracle attack to recover plaintext. GCM appends a
**16-byte authentication tag** computed over the ciphertext, so any single-bit
change makes decryption fail with an `InvalidTag` error instead of silently
returning garbage. Flip one byte of `vault.json` and the tool refuses to
decrypt — that is the whole point of the "GCM" part.

Each write uses a fresh random 12-byte nonce, so the same plaintext never
encrypts to the same ciphertext.

### 4. Strong passwords with `secrets` — not `random`

`python vault.py gen` builds passwords with `secrets.choice`, using a wide
alphabet (upper/lower/digits/symbols), guaranteeing at least one character from
each class, and shuffling with a CSPRNG. Length defaults to 20.

Why `secrets` and not `random`? `random` is the **Mersenne Twister**, a
pseudo-random generator designed for simulations, not security. Its entire
state can be recovered after observing enough outputs, making "random"
passwords predictable. `secrets` draws from the operating system's
**cryptographically secure random source** (`os.urandom`, i.e. `/dev/urandom`
or the OS's equivalent), which is designed to be unpredictable to an attacker.
Generating secrets is exactly the use case `secrets` exists for.

---

## Vault file format

`vault.json` is readable JSON with four sections:

```jsonc
{
  "version": 1,
  "kdf":          { "type": "argon2id", "salt_b64": "...", /* time/memory/parallelism/hash_len */ },
  "master_hash":  "$argon2id$v=19$m=65536,t=3,p=4$...",   // only the hash, never the password
  "cipher":       { "algorithm": "AES-256-GCM", "nonce_b64": "...", "data_b64": "..." }
}
```

- `kdf.salt_b64` is the random salt for key derivation (a salt is public, not a
  secret). The KDF parameters are stored so the same key can always be derived.
- `master_hash` is used only to *verify* the password on unlock.
- `cipher.data_b64` is `ciphertext ‖ 16-byte tag`; `nonce_b64` is fresh per write.

Each unlock performs two Argon2id computations: one verifies `master_hash`
using its embedded salt and parameters; the other derives the AES key using the
separate KDF salt and supported parameters. This separates the two purposes but
adds to unlock cost.

---

## Master-password and key-derivation tests

From the repository root, run:

```bash
python -m unittest discover -s tests -v
```

`tests/test_master_password.py` checks acceptance of a correct password and
rejection of a wrong password with exit code 1. `tests/test_key_derivation.py`
checks reproducible derivation, changes after changing the password or salt,
32-byte output, and rejection of malformed or unsupported KDF inputs. Error
handling tests check both the exit code and the explanatory message.

The current suite has 14 test methods, with additional cases run as subtests.
Fixtures use a fixed salt and a fictional password so that inputs are controlled;
real vault initialization still uses random salts. These unit tests do not read
or write a real vault file, test the complete CLI, or establish correctness of
AES-GCM, RSA sharing, or the breach-check service. The wrong-password test may
print `error: Wrong master password.` while still passing because the exit is
expected and caught.

---

## Bonus A — share one entry with RSA-OAEP

`share` encrypts a single entry for a teammate's **public key** using
RSA-OAEP-SHA256, so only their **private key** can open it:

```bash
python vault.py keygen --name alice                 # alice.pub.pem / alice.priv.pem
python vault.py share github --to bob --pubkey bob.pub.pem
python vault.py open github.bob.share --privkey bob.priv.pem
```

Entries are tiny, so OAEP encrypts them directly; for larger payloads a hybrid
scheme (random AES key wrapped by RSA) would be used, but that is unnecessary
here. The private key files are written *unencrypted* purely for this demo —
in a real deployment they would be passphrase-protected.

## Bonus B — breach check with k-anonymity (Have I Been Pwned)

`breach` checks a password against Have I Been Pwned **without sending the
password or its full hash**:

```bash
python vault.py breach                 # prompts for a password
python vault.py check github           # checks a stored entry's password
```

Only the **first 5 hex characters** of the SHA-1 digest are sent to
`api.pwnedpasswords.com/range/{prefix}`. The server responds with every matching
suffix in that range; we compare locally. The 5-character prefix selects a
bucket of roughly 500 passwords, so the server learns "your password is one of
~500 candidates" but not which one — this is **k-anonymity**. The full hash and
the password never leave your machine.

---

## Security model (summary)

| Threat | Protected? |
|---|---|
| Vault file stolen | ✅ only ciphertext + Argon2id hash |
| Wrong master password | ✅ rejected |
| Vault tampering | ✅ GCM authentication fails loudly |
| Keylogger | ❌ |
| Weak master password | ❌ |
| Screen / shoulder reading | ❌ |
| Malware as your user | ❌ |

## Dependencies

- `argon2-cffi` — Argon2id password hashing and key derivation.
- `cryptography` — AES-256-GCM and RSA-OAEP.
- Python stdlib — `secrets`, `hashlib`, `json`, `argparse`, `getpass`, `urllib`.
