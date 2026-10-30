# Vault — a command-line password manager

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

### 1. Master password stored with Argon2id — not SHA-256, not AES

The master password is hashed with **Argon2id** (`argon2-cffi`) and stored as a
`$argon2id$...` string. A wrong password is rejected on unlock.

Why Argon2id and not SHA-256? Because they solve different problems. SHA-256 is
a *fast* general-purpose hash: that is exactly the wrong property for hashing
human-chosen passwords. A fast hash means an attacker with the file can try
billions of guesses per second on a GPU. Argon2id is **memory-hard**: each guess
must allocate tens of megabytes of RAM, so guessing cannot be parallelised
across GPU cores or ASICs. It is also salted (two identical passwords produce
different hashes, and precomputed rainbow tables are useless) and has tunable
cost parameters that we set to 64 MiB / t=3 / p=4.

Why not AES? AES is not a hash at all — it is a *reversible* cipher, and we must
*never* be able to recover the master password from what is stored. Argon2id is
one-way.

### 2. Encryption key derived from the master password — no key file

The AES-256 key that encrypts the vault is derived from the master password with
Argon2id used as a **key-derivation function (KDF)**. It is computed on demand
and never written to disk. There is no key file anywhere.

Why derive instead of generating a random key and saving it next to the vault?
Because a saved key file is *itself a secret stored on disk*. If the attacker
steals the vault file, they steal the key file too, and the vault opens — the
master password becomes irrelevant. Deriving the key from the password means
the **only secret is in the user's head**: stealing the disk gives the attacker
nothing but ciphertext they cannot open without guessing the password. The
trade-off is that the password must be strong, which is why we hash it with
Argon2id and encourage length.

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

The master password is derived twice per unlock (once for verification, once
for the key) — a deliberate, slightly slower choice that keeps verification and
key derivation as two clean, independent primitives.

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
