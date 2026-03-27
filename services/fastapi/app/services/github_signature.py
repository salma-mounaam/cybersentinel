import hashlib
import hmac
from typing import Optional


def verify_github_signature(
    secret: str,
    raw_body: bytes,
    signature_256: Optional[str]
) -> bool:
    if not secret:
        return False

    if not signature_256:
        return False

    expected_signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature_256)