"""Carry the stored secrets to another machine, encrypted under a passphrase.

WHY THIS EXISTS. Every token this app holds is sealed with Windows DPAPI, which keys off
the current user ON THIS MACHINE — dpapi.py says so in its own docstring: "Nothing here is
portable to another machine, by design." That is the right default, and it is also exactly
what makes a laptop migration painful: copy config/settings.local.json to a new machine and
every connector is silently dead, because CryptUnprotectData simply fails and unprotect()
returns None.

So the secrets are unsealed here, re-sealed under a passphrase the operator types, and
re-sealed again with the NEW machine's DPAPI on arrival. The passphrase is never stored,
never written to disk, and never travels with the bundle.

WHY THIS CONSTRUCTION, and not a library. `cryptography` is not installed and the app
otherwise needs no crypto at all; adding a binary wheel — and a pip install that must
succeed before a migration can even start — is a worse trade than a small, standard
construction over the standard library's own vetted primitives. What is used here is
ordinary and not invented:

  * PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP's 2023 figure for SHA-256), 16-byte
    random salt, deriving 64 bytes: the first 32 encrypt, the last 32 authenticate.
    Separate keys, because reusing one key for both is the classic way this goes wrong.
  * A keystream from HMAC-SHA256(key_enc, nonce || counter) — counter mode over a PRF,
    which is what HMAC is. XORed with the plaintext.
  * ENCRYPT-THEN-MAC: the tag covers the version, the iteration count, the salt, the
    nonce AND the ciphertext, so none of them can be altered — an attacker cannot quietly
    drop the iteration count to 1 and brute-force the passphrase.
  * The tag is verified with hmac.compare_digest BEFORE a single byte is decrypted.

WHAT IS IN THE BUNDLE, and what is deliberately left out. Only the credentials that are
worth moving: measured on this machine, the SolarWinds token is a JWT with NO exp claim
(non-expiring), and the Graph secret and the Nagios credential are static strings. The
OneDesk bearer is a short-lived JWT — carrying a dead token adds risk for no benefit, so
it is skipped and re-grabbed with the bookmarklet on the new machine.

THE BUNDLE IS STILL A SECRET. It is a brute-forceable file: a weak passphrase is the whole
of its security. Put it somewhere you are content to have it, use a real passphrase, and
delete it once the new machine works.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

VERSION = 1
KDF_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 16

# The credentials worth moving, with why. Anything not listed is re-established on the new
# machine rather than carried.
DURABLE_SECRETS = {
    "SwTokenEnc": "SolarWinds API token — a JWT with no exp claim, so it does not expire",
    "SecretEnc": "Microsoft Graph client secret — set in the app registration",
    "NagiosAuthEnc": "Nagios basic credential — a static user:password",
}

SHORT_LIVED_SECRETS = {
    "TaskHubTokenEnc": "OneDesk bearer — expires in hours; re-grab with the bookmarklet",
}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(str(text).encode("ascii"))


def _derive(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """64 bytes from the passphrase: 32 to encrypt with, 32 to authenticate with."""
    material = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt,
                                   iterations, dklen=64)
    return material[:32], material[32:]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 in counter mode. A PRF keyed once, run over a counter."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _tag(key: bytes, header: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Authenticate everything a reader would otherwise have to trust."""
    return hmac.new(key, header + b"|" + nonce + b"|" + ciphertext, hashlib.sha256).digest()


def pack(secrets_by_key: dict, passphrase: str, note: str = "") -> bytes:
    """Seal {settings key: plaintext secret} into a portable bundle."""
    if not passphrase or len(passphrase) < 8:
        raise ValueError("The passphrase must be at least 8 characters.")
    if not secrets_by_key:
        raise ValueError("There is nothing to put in the bundle.")

    payload = json.dumps({
        "secrets": secrets_by_key,
        "note": note,
        "packedAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }, ensure_ascii=False).encode("utf-8")

    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key_enc, key_mac = _derive(passphrase, salt, KDF_ITERATIONS)
    ciphertext = bytes(a ^ b for a, b in
                       zip(payload, _keystream(key_enc, nonce, len(payload))))

    header = json.dumps({"v": VERSION, "kdf": "pbkdf2-sha256",
                         "iterations": KDF_ITERATIONS, "salt": _b64(salt)},
                        sort_keys=True).encode("utf-8")
    envelope = {
        "v": VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        # Covers the header too, so the iteration count cannot be weakened in transit.
        "tag": _b64(_tag(key_mac, header, nonce, ciphertext)),
        "keys": sorted(secrets_by_key),        # names only — never the values
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def unpack(blob: bytes, passphrase: str) -> dict:
    """Open a bundle. Raises ValueError on a wrong passphrase or a tampered file."""
    try:
        envelope = json.loads(blob.decode("utf-8"))
    except Exception as exc:                          # noqa: BLE001
        raise ValueError(f"That is not a secrets bundle: {exc}") from None

    if int(envelope.get("v") or 0) != VERSION:
        raise ValueError(f"Bundle version {envelope.get('v')} is not supported.")
    iterations = int(envelope.get("iterations") or 0)
    if iterations < 100_000:
        # Refused rather than honoured: a low count is either corruption or somebody
        # trying to make the passphrase cheap to guess.
        raise ValueError("That bundle asks for too few KDF iterations to be trusted.")

    salt = _unb64(envelope["salt"])
    nonce = _unb64(envelope["nonce"])
    ciphertext = _unb64(envelope["ciphertext"])
    key_enc, key_mac = _derive(passphrase, salt, iterations)

    header = json.dumps({"v": int(envelope["v"]), "kdf": str(envelope["kdf"]),
                         "iterations": iterations, "salt": envelope["salt"]},
                        sort_keys=True).encode("utf-8")
    want = _unb64(envelope["tag"])
    got = _tag(key_mac, header, nonce, ciphertext)
    # Checked BEFORE decrypting, and in constant time.
    if not hmac.compare_digest(want, got):
        raise ValueError("Wrong passphrase, or the bundle has been altered.")

    plain = bytes(a ^ b for a, b in
                  zip(ciphertext, _keystream(key_enc, nonce, len(ciphertext))))
    try:
        opened = json.loads(plain.decode("utf-8"))
    except Exception:                                 # noqa: BLE001
        raise ValueError("The bundle opened but its contents are not readable.") from None
    return opened


# --------------------------------------------------------------------------
# Using it against the real settings file
# --------------------------------------------------------------------------
def collect(include_short_lived: bool = False) -> tuple[dict, list]:
    """Unseal what DPAPI will give us. Returns (secrets, notes-about-what-was-skipped)."""
    from . import config, dpapi

    cfg = config.load()
    wanted = dict(DURABLE_SECRETS)
    if include_short_lived:
        wanted.update(SHORT_LIVED_SECRETS)

    out, notes = {}, []
    for key, why in wanted.items():
        blob = cfg.get(key)
        if not blob:
            notes.append(f"{key}: nothing stored")
            continue
        value = dpapi.unprotect(blob)
        if value is None:
            notes.append(f"{key}: stored but this account cannot decrypt it")
            continue
        out[key] = value
    for key, why in (SHORT_LIVED_SECRETS if not include_short_lived else {}).items():
        if cfg.get(key):
            notes.append(f"{key}: skipped on purpose — {why}")
    return out, notes


def apply(opened: dict) -> list:
    """Re-seal the opened secrets with THIS machine's DPAPI and write them to settings."""
    from . import config, dpapi

    changes, done = {}, []
    for key, value in (opened.get("secrets") or {}).items():
        if not isinstance(value, str) or not value:
            continue
        changes[key] = dpapi.protect(value)
        done.append(key)
    if changes:
        config.update(**changes)
    return done
