"""A small command-line password manager.

Building blocks (all from established libraries, none hand-rolled):

  1. Master password hashed with Argon2id  (argon2-cffi)  -> stored as a
     "$argon2id$..." string, never recoverable.
  2. Encryption key derived from the master password (Argon2id as a KDF).
     No key file exists anywhere on disk.
  3. Vault encrypted with AES-256-GCM (cryptography) -> authenticated
     encryption, any tampering is detected at decrypt time.
  4. Strong password generation with the `secrets` module (CSPRNG).

Bonus:
  A. Share one entry with RSA-OAEP (a teammate's public key).
  B. Have I Been Pwned breach check via k-anonymity (SHA-1 prefix only).

Usage examples:
    python vault.py init
    python vault.py add github --user alice
    python vault.py get github
    python vault.py gen --length 20
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import string
import sys
import urllib.error
import urllib.request
from getpass import getpass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_FILE = "vault.json"

# Argon2id parameters (OWASP-aligned). Used for BOTH the master-password hash
# and the key derivation, so they cost the same for an attacker.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32

NONCE_LEN = 12          # GCM standard nonce length
KDF_SALT_LEN = 16       # 128-bit random salt for the KDF
DEFAULT_PW_LENGTH = 20

SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?/"

# The master-password hash is verified with PasswordHasher (which embeds its
# parameters in the "$argon2id$..." string). Configured once, reused everywhere.
PH = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def die(message: str) -> "None":
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def prompt_master_password() -> str:
    """Read the master password. Never echo it to the terminal.

    The VAULT_PASSWORD environment variable is supported only as a convenience
    for scripts/tests; interactive use always prompts via getpass().
    """
    env = os.environ.get("VAULT_PASSWORD")
    if env:
        return env
    return getpass("Master password: ")


# --------------------------------------------------------------------------- #
# Vault (de)serialization
# --------------------------------------------------------------------------- #

def read_vault(path: Path) -> dict:
    if not path.exists():
        die(f"No vault found at {path}. Run `python vault.py init` first.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        die(f"Vault file is not valid JSON (tampered?): {exc}")


def write_vault(path: Path, vault: dict) -> None:
    """Write atomically so a crash never leaves a half-written vault."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(vault, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Crypto building blocks
# --------------------------------------------------------------------------- #

def derive_key(vault: dict, password: str) -> bytes:
    """Derive the AES-256 key from the master password using Argon2id.

    The salt is stored in the vault header (a salt is not a secret). The key
    itself is never written to disk.
    """
    if "kdf" not in vault:
        die("Vault is missing KDF parameters.")

    kdf = vault["kdf"]
    if not isinstance(kdf,dict):
        die("Vault KDF parameters must be an object.")

    salt = base64.b64decode(kdf["salt_b64"])
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=kdf["hash_len"],
        type=Type.ID,
    )


def verify_master(vault: dict, password: str) -> None:
    """Reject a wrong master password against the stored Argon2id hash."""
    try:
        PH.verify(vault["master_hash"], password)
    except VerifyMismatchError:
        die("Wrong master password.")
    except Exception as exc:  # malformed hash in a tampered file, etc.
        die(f"Could not verify master password: {exc}")


def encrypt_entries(entries: dict, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt the entries dict with AES-256-GCM. Returns (nonce, data).

    `data` is ciphertext || 16-byte tag. A fresh random nonce is used on every
    write, so identical plaintext never produces identical ciphertext.
    """
    plaintext = json.dumps(entries, sort_keys=True, ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(NONCE_LEN)
    data = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, data


def decrypt_entries(vault: dict, key: bytes) -> dict:
    """Decrypt the vault. GCM authentication fails loudly on any tampering."""
    cipher = vault["cipher"]
    nonce = base64.b64decode(cipher["nonce_b64"])
    data = base64.b64decode(cipher["data_b64"])
    try:
        plaintext = AESGCM(key).decrypt(nonce, data, None)
    except InvalidTag:
        die("Vault authentication failed: the file was tampered with "
            "or the key is wrong. Nothing was decrypted.")
    return json.loads(plaintext.decode("utf-8"))


def load_and_unlock(path: Path, password: str) -> tuple[dict, bytes, dict]:
    """Verify the master password, derive the key, decrypt -> (vault, key, entries)."""
    vault = read_vault(path)
    verify_master(vault, password)
    key = derive_key(vault, password)
    entries = decrypt_entries(vault, key)
    return vault, key, entries


def save_entries(path: Path, vault: dict, key: bytes, entries: dict) -> None:
    nonce, data = encrypt_entries(entries, key)
    vault["cipher"] = {
        "algorithm": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "data_b64": base64.b64encode(data).decode("ascii"),
    }
    write_vault(path, vault)


# --------------------------------------------------------------------------- #
# Password generation (secrets, NOT random)
# --------------------------------------------------------------------------- #

def generate_password(length: int = DEFAULT_PW_LENGTH, symbols: bool = True) -> str:
    """Generate a strong password using the `secrets` CSPRNG.

    Guarantees at least one character from each selected class, then fills the
    rest uniformly from the combined alphabet and shuffles with a CSPRNG.
    """
    if length < 4:
        die("Password length must be at least 4.")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    alphabet = "".join(pools)

    # Ensure at least one character from every pool.
    chars = [secrets.choice(pool) for pool in pools]
    # Fill the remainder from the whole alphabet.
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # Shuffle using a cryptographically secure source.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Bonus A: share an entry with RSA-OAEP
# --------------------------------------------------------------------------- #

_RSA_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def load_public_key(path: str):
    try:
        data = Path(path).read_bytes()
        return serialization.load_pem_public_key(data)
    except (OSError, ValueError) as exc:
        die(f"Could not read public key {path}: {exc}")


def load_private_key(path: str):
    try:
        data = Path(path).read_bytes()
        return serialization.load_pem_private_key(data, password=None)
    except (OSError, ValueError) as exc:
        die(f"Could not read private key {path}: {exc}")


def cmd_share(args) -> None:
    path = Path(args.file)
    vault, _key, entries = load_and_unlock(path, prompt_master_password())
    entry = entries["entries"].get(args.site)
    if entry is None:
        die(f"No entry for '{args.site}'.")

    payload = {
        "site": args.site,
        "username": entry["username"],
        "password": entry["password"],
        "shared_to": args.to,
    }
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    public_key = load_public_key(args.pubkey)
    ciphertext = public_key.encrypt(plaintext, _RSA_OAEP)

    out = Path(args.out) if args.out else Path(f"{args.site}.{args.to}.share")
    doc = {
        "version": 1,
        "to": args.to,
        "algorithm": "RSA-OAEP-SHA256",
        "data_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"Shared '{args.site}' with '{args.to}' -> {out}")


def cmd_open(args) -> None:
    try:
        doc = json.loads(Path(args.share_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"Could not read share file {args.share_file}: {exc}")

    private_key = load_private_key(args.privkey)
    try:
        plaintext = private_key.decrypt(base64.b64decode(doc["data_b64"]), _RSA_OAEP)
    except ValueError:
        die("Decryption failed: wrong private key, or the share file was tampered with.")

    payload = json.loads(plaintext.decode("utf-8"))
    print(f"shared by : {payload.get('shared_to', '?')}")
    print(f"site      : {payload['site']}")
    print(f"username  : {payload['username']}")
    print(f"password  : {payload['password']}")


def cmd_keygen(args) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    priv_path = outdir / f"{args.name}.priv.pem"
    pub_path = outdir / f"{args.name}.pub.pem"

    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Private key : {priv_path}  (KEEP SECRET - never commit)")
    print(f"Public key  : {pub_path}  (share this)")


# --------------------------------------------------------------------------- #
# Bonus B: Have I Been Pwned via k-anonymity
# --------------------------------------------------------------------------- #

def pwned_count(password: str) -> int:
    """Return how many times `password` appears in HIBP breaches (0 if never).

    Only the first 5 hex chars of the SHA-1 digest are sent to the API, so the
    full hash (and the password) never leave the machine.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "vault.py-course-project"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as exc:
        die(f"Breach check failed (network): {exc}")

    for line in text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count.strip())
    return 0


def cmd_breach(args) -> None:
    password = args.password or getpass("Password to check: ")
    count = pwned_count(password)
    if count:
        print(f"FOUND in {count} breaches - do not use this password.")
    else:
        print("Not found in the Have I Been Pwned dataset.")


def cmd_check(args) -> None:
    path = Path(args.file)
    _vault, _key, entries = load_and_unlock(path, prompt_master_password())
    entry = entries["entries"].get(args.site)
    if entry is None:
        die(f"No entry for '{args.site}'.")
    count = pwned_count(entry["password"])
    if count:
        print(f"'{args.site}' password found in {count} breaches - change it.")
    else:
        print(f"'{args.site}' password not found in the HIBP dataset.")


# --------------------------------------------------------------------------- #
# Core commands
# --------------------------------------------------------------------------- #

def cmd_init(args) -> None:
    path = Path(args.file)
    if path.exists():
        die(f"{path} already exists - refusing to overwrite it.")

    env = os.environ.get("VAULT_PASSWORD")
    if env:
        password = env
    else:
        password = getpass("Choose a master password: ")
        if not password:
            die("Master password must not be empty.")
        if password != getpass("Confirm master password: "):
            die("Passwords do not match.")

    # 1) Hash the master password with Argon2id (stored as a string).
    master_hash = PH.hash(password)
    # 2) Derive a separate encryption key from the master password.
    salt = os.urandom(KDF_SALT_LEN)
    key = derive_key({"kdf": {
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "time_cost": ARGON2_TIME_COST,
        "memory_cost": ARGON2_MEMORY_COST,
        "parallelism": ARGON2_PARALLELISM,
        "hash_len": ARGON2_HASH_LEN,
    }}, password)

    entries = {"entries": {}}
    nonce, data = encrypt_entries(entries, key)
    vault = {
        "version": 1,
        "kdf": {
            "type": "argon2id",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "hash_len": ARGON2_HASH_LEN,
        },
        "master_hash": master_hash,
        "cipher": {
            "algorithm": "AES-256-GCM",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "data_b64": base64.b64encode(data).decode("ascii"),
        },
    }
    write_vault(path, vault)
    print(f"Vault created at {path}. Remember your master password - it cannot be recovered.")


def cmd_unlock(args) -> None:
    path = Path(args.file)
    _vault, _key, entries = load_and_unlock(path, prompt_master_password())
    print(f"Vault unlocked ({len(entries['entries'])} entries).")


def cmd_add(args) -> None:
    path = Path(args.file)
    password = args.password
    generated = False
    if password is None:
        password = generate_password(args.length)
        generated = True

    vault, key, entries = load_and_unlock(path, prompt_master_password())
    entries["entries"][args.site] = {
        "username": args.username or "",
        "password": password,
    }
    save_entries(path, vault, key, entries)

    if generated:
        print(f"Added '{args.site}' with a generated password:")
        print(f"  {password}")
        print("  (save it somewhere safe - it is shown only now)")
    else:
        print(f"Added/updated '{args.site}'.")


def cmd_list(args) -> None:
    path = Path(args.file)
    _vault, _key, entries = load_and_unlock(path, prompt_master_password())
    if not entries["entries"]:
        print("(vault is empty)")
        return
    for site in sorted(entries["entries"]):
        user = entries["entries"][site]["username"]
        print(f"{site}" + (f"  ({user})" if user else ""))


def cmd_get(args) -> None:
    path = Path(args.file)
    _vault, _key, entries = load_and_unlock(path, prompt_master_password())
    entry = entries["entries"].get(args.site)
    if entry is None:
        die(f"No entry for '{args.site}'.")
    print(f"site     : {args.site}")
    print(f"username : {entry['username']}")
    print(f"password : {entry['password']}")


def cmd_delete(args) -> None:
    path = Path(args.file)
    vault, key, entries = load_and_unlock(path, prompt_master_password())
    if args.site not in entries["entries"]:
        die(f"No entry for '{args.site}'.")
    del entries["entries"][args.site]
    save_entries(path, vault, key, entries)
    print(f"Deleted '{args.site}'.")


def cmd_gen(args) -> None:
    print(generate_password(args.length, symbols=not args.no_symbols))


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    # A shared `--file` option attached to every subcommand, so it works both
    # BEFORE the subcommand (`vault.py --file x init`) and AFTER it
    # (`vault.py init --file x`). SUPPRESS stops the subcommand copy from
    # clobbering a value already set by the top-level parser.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--file", dest="file", default=argparse.SUPPRESS,
                        help=f"Vault file path (default: {DEFAULT_FILE}).")

    parser = argparse.ArgumentParser(
        prog="vault.py",
        description="Command-line password manager (Argon2 + AES-256-GCM).",
    )
    parser.add_argument("--file", dest="file", default=DEFAULT_FILE,
                        help=f"Vault file path (default: {DEFAULT_FILE}).")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", parents=[common], help="Create a new vault and set the master password.")
    sub.add_parser("unlock", parents=[common], help="Verify the master password and show a summary.")

    ap = sub.add_parser("add", parents=[common], help="Add or update a site entry.")
    ap.add_argument("site")
    ap.add_argument("--user", dest="username", default=None, help="Username.")
    ap.add_argument("--password", default=None,
                    help="Password (omit to generate a strong one).")
    ap.add_argument("--length", type=int, default=DEFAULT_PW_LENGTH,
                    help="Length for a generated password.")

    sub.add_parser("list", parents=[common], help="List all stored sites.")

    gp = sub.add_parser("get", parents=[common], help="Show username and password for a site.")
    gp.add_argument("site")

    dp = sub.add_parser("delete", parents=[common], help="Delete a site entry.")
    dp.add_argument("site")

    g2 = sub.add_parser("gen", parents=[common], help="Generate a strong password.")
    g2.add_argument("--length", type=int, default=DEFAULT_PW_LENGTH)
    g2.add_argument("--no-symbols", action="store_true",
                    help="Exclude symbols from the alphabet.")

    sp = sub.add_parser("share", parents=[common], help="(Bonus) Encrypt one entry for a teammate.")
    sp.add_argument("site")
    sp.add_argument("--to", required=True, help="Recipient name.")
    sp.add_argument("--pubkey", required=True, help="Recipient's public key (PEM).")
    sp.add_argument("--out", default=None, help="Output file.")

    op = sub.add_parser("open", parents=[common], help="(Bonus) Decrypt a shared entry.")
    op.add_argument("share_file")
    op.add_argument("--privkey", required=True, help="Your private key (PEM).")

    kp = sub.add_parser("keygen", parents=[common], help="(Bonus) Generate an RSA keypair.")
    kp.add_argument("--name", required=True)
    kp.add_argument("--outdir", default=".")

    bp = sub.add_parser("breach", parents=[common], help="(Bonus) Check a password against HIBP.")
    bp.add_argument("password", nargs="?", default=None)

    cp = sub.add_parser("check", parents=[common], help="(Bonus) Check a stored password against HIBP.")
    cp.add_argument("site")

    return parser


COMMANDS = {
    "init": cmd_init,
    "unlock": cmd_unlock,
    "add": cmd_add,
    "list": cmd_list,
    "get": cmd_get,
    "delete": cmd_delete,
    "gen": cmd_gen,
    "share": cmd_share,
    "open": cmd_open,
    "keygen": cmd_keygen,
    "breach": cmd_breach,
    "check": cmd_check,
}


def main() -> None:
    args = build_parser().parse_args()
    try:
        COMMANDS[args.command](args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
