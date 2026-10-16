"""Secure Secrets Exchange end-to-end format (sse-e2e-v1), Python.

pip install cryptography
Encrypt before you buy "create"; give the recipient share_url_base + "#" + key.
For "request", give the sender request_url + "#" + key, then decrypt what retrieve returns.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "sse-e2e-v1."


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def new_key() -> str:
    """32 random bytes, base64url without padding (43 characters). Goes after # in the link."""
    return b64u(AESGCM.generate_key(bit_length=256))


def encrypt(secret: str, key: str) -> str:
    iv = os.urandom(12)
    return PREFIX + b64u(iv + AESGCM(ub64u(key)).encrypt(iv, secret.encode("utf-8"), None))


def decrypt(payload: str, key: str) -> str:
    if not payload.startswith(PREFIX):
        raise ValueError("not an sse-e2e-v1 payload")
    raw = ub64u(payload[len(PREFIX):])
    return AESGCM(ub64u(key)).decrypt(raw[:12], raw[12:], None).decode("utf-8")


if __name__ == "__main__":
    k = new_key()
    p = encrypt("sk-example-not-a-real-key", k)
    assert decrypt(p, k) == "sk-example-not-a-real-key"
    print("payload for create:", p)
    print("append to share_url_base: #" + k)
