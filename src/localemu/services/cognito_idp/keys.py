"""RSA key management for Cognito user pools.

Each user pool gets its own RSA key pair. The private key signs JWTs,
the public key is served via the JWKS endpoint for verification.
"""

import base64
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, str]:
    """Generate an RSA key pair and a key ID (kid).

    Returns:
        (private_key, kid) tuple
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    kid = str(uuid.uuid4())
    return private_key, kid


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize private key to PEM format (for PyJWT)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_to_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict:
    """Convert an RSA public key to JWK format for the JWKS endpoint.

    Returns a dict matching the AWS Cognito JWKS format.
    """
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }


def _int_to_base64url(num: int) -> str:
    """Convert a large integer to base64url encoding (no padding)."""
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(num_bytes).rstrip(b"=").decode("ascii")
