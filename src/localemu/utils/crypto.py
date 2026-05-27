import datetime as _dt
import ipaddress as _ip
import logging
import os
import re
import threading

from asn1crypto import algos, cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .files import TMP_FILES, file_exists_not_empty, load_file, new_tmp_file, save_file
from .strings import short_uid, to_bytes, to_str
from .sync import synchronized
from .urls import localemu_host

LOG = logging.getLogger(__name__)

# block size for symmetric encrypt/decrypt operations
BLOCK_SIZE = 16

# lock for creating certificate files
SSL_CERT_LOCK = threading.RLock()

# markers that indicate the start/end of sections in PEM cert files
PEM_CERT_START = "-----BEGIN CERTIFICATE-----"
PEM_CERT_END = "-----END CERTIFICATE-----"
PEM_KEY_START_REGEX = r"-----BEGIN(.*)PRIVATE KEY-----"
PEM_KEY_END_REGEX = r"-----END(.*)PRIVATE KEY-----"

OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_RSAES_OAEP = "1.2.840.113549.1.1.7"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


def _build_self_signed_cert(host: str, serial_number: int) -> tuple[str, str]:
    """Generate a self-signed RSA-2048 / SHA-256 server cert for ``host``.

    Returns ``(cert_pem, key_pem)``. Uses the cryptography library directly
    (pyOpenSSL 26 removed the X509.add_extensions builder path this module
    used historically). The SAN list always contains ``localhost`` and the
    loopback IP so virtual-hosted-style local URLs verify; an additional
    DNS entry for ``host`` is added when it is a hostname distinct from
    ``localhost``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Some-Locality"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalEmu Org"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Testing"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    san_general_names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName("test.localhost.atlassian.io"),
    ]
    if host and host != "localhost":
        try:
            san_general_names.append(x509.IPAddress(_ip.ip_address(host)))
        except ValueError:
            san_general_names.append(x509.DNSName(host))
    san_general_names.append(x509.IPAddress(_ip.IPv4Address("127.0.0.1")))

    now = _dt.datetime.now(_dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=2 * 365))
        .add_extension(x509.SubjectAlternativeName(san_general_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return cert_pem, key_pem


@synchronized(lock=SSL_CERT_LOCK)
def generate_ssl_cert(
    target_file=None,
    overwrite=False,
    random=False,
    return_content=False,
    serial_number=None,
):
    def all_exist(*files):
        return all(os.path.exists(f) for f in files)

    def store_cert_key_files(base_filename):
        key_file_name = f"{base_filename}.key"
        cert_file_name = f"{base_filename}.crt"
        # TODO: Cleaner code to load the cert dynamically
        # extract key and cert from target_file and store into separate files
        content = load_file(target_file)
        key_start = re.search(PEM_KEY_START_REGEX, content)
        key_start = key_start.group(0)
        key_end = re.search(PEM_KEY_END_REGEX, content)
        key_end = key_end.group(0)
        key_content = content[content.index(key_start) : content.index(key_end) + len(key_end)]
        cert_content = content[
            content.index(PEM_CERT_START) : content.rindex(PEM_CERT_END) + len(PEM_CERT_END)
        ]
        save_file(key_file_name, key_content)
        save_file(cert_file_name, cert_content)
        return cert_file_name, key_file_name

    if target_file and not overwrite and file_exists_not_empty(target_file):
        try:
            cert_file_name, key_file_name = store_cert_key_files(target_file)
        except Exception as e:
            # fall back to temporary files if we cannot store/overwrite the files above
            LOG.info(
                "Error storing key/cert SSL files (falling back to random tmp file names): %s", e
            )
            target_file_tmp = new_tmp_file()
            cert_file_name, key_file_name = store_cert_key_files(target_file_tmp)
        if all_exist(cert_file_name, key_file_name):
            return target_file, cert_file_name, key_file_name
    if random and target_file:
        if "." in target_file:
            target_file = target_file.replace(".", f".{short_uid()}.", 1)
        else:
            target_file = f"{target_file}.{short_uid()}"

    host_definition = localemu_host()
    # macOS requirements for self-signed serverAuth certificates:
    # https://support.apple.com/en-us/HT210176
    serial_number = serial_number or 1001
    cert_pem_str, key_pem_str = _build_self_signed_cert(
        host=host_definition.host, serial_number=serial_number
    )
    cert_file_content = cert_pem_str.strip()
    key_file_content = key_pem_str.strip()
    file_content = f"{key_file_content}\n{cert_file_content}"
    if target_file:
        key_file_name = f"{target_file}.key"
        cert_file_name = f"{target_file}.crt"
        # check existence to avoid permission denied issues:
        # https://github.com/localstack/localstack/issues/1607
        if not all_exist(target_file, key_file_name, cert_file_name):
            for i in range(2):
                try:
                    save_file(target_file, file_content)
                    save_file(key_file_name, key_file_content)
                    save_file(cert_file_name, cert_file_content)
                    break
                except Exception as e:
                    if i > 0:
                        raise
                    LOG.info(
                        "Unable to store certificate file under %s, using tmp file instead: %s",
                        target_file,
                        e,
                    )
                    # Fix for https://github.com/localstack/localstack/issues/1743
                    target_file = f"{new_tmp_file()}.pem"
                    key_file_name = f"{target_file}.key"
                    cert_file_name = f"{target_file}.crt"
            TMP_FILES.append(target_file)
            TMP_FILES.append(key_file_name)
            TMP_FILES.append(cert_file_name)
        if not return_content:
            return target_file, cert_file_name, key_file_name
    return file_content


def pad(s: bytes) -> bytes:
    return s + to_bytes((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE))


def unpad(s: bytes) -> bytes:
    return s[0 : -s[-1]]


def encrypt(key: bytes, message: bytes, iv: bytes = None, aad: bytes = None) -> tuple[bytes, bytes]:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    encrypted = encryptor.update(pad(message)) + encryptor.finalize()
    return encrypted, encryptor.tag


def decrypt(
    key: bytes, encrypted: bytes, iv: bytes = None, tag: bytes = None, aad: bytes = None
) -> bytes:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = unpad(decrypted)
    return decrypted


def pkcs7_envelope_encrypt(plaintext: bytes, recipient_pubkey: RSAPublicKey) -> bytes:
    """
    Create a PKCS7 wrapper of some plaintext decryptable by recipient_pubkey.  Uses RSA-OAEP with SHA-256
    to encrypt the AES-256-CBC content key.  Hazmat's PKCS7EnvelopeBuilder doesn't support RSA-OAEP with SHA-256,
    so we need to build the pieces manually and then put them together in an envelope with asn1crypto.
    """

    # Encrypt the plaintext with an AES session key, then encrypt the session key to the recipient_pubkey
    session_key = os.urandom(32)
    iv = os.urandom(16)
    encrypted_session_key = recipient_pubkey.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    encrypted_content = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Now put together the envelope.
    # Add the recipient with their copy of the session key
    recipient_identifier = cms.RecipientIdentifier(
        name="issuer_and_serial_number",
        value=cms.IssuerAndSerialNumber(
            {
                "issuer": asn1_x509.Name.build({"common_name": "recipient"}),
                "serial_number": 1,
            }
        ),
    )
    key_enc_algorithm = cms.KeyEncryptionAlgorithm(
        {
            "algorithm": OID_RSAES_OAEP,
            "parameters": algos.RSAESOAEPParams(
                {
                    "hash_algorithm": algos.DigestAlgorithm(
                        {
                            "algorithm": OID_SHA256,
                        }
                    ),
                    "mask_gen_algorithm": algos.MaskGenAlgorithm(
                        {
                            "algorithm": OID_MGF1,
                            "parameters": algos.DigestAlgorithm(
                                {
                                    "algorithm": OID_SHA256,
                                }
                            ),
                        }
                    ),
                }
            ),
        }
    )
    recipient_info = cms.KeyTransRecipientInfo(
        {
            "version": "v0",
            "rid": recipient_identifier,
            "key_encryption_algorithm": key_enc_algorithm,
            "encrypted_key": encrypted_session_key,
        }
    )

    # Add the encrypted content
    content_enc_algorithm = cms.EncryptionAlgorithm(
        {
            "algorithm": OID_AES256_CBC,
            "parameters": core.OctetString(iv),
        }
    )
    encrypted_content_info = cms.EncryptedContentInfo(
        {
            "content_type": "data",
            "content_encryption_algorithm": content_enc_algorithm,
            "encrypted_content": encrypted_content,
        }
    )
    enveloped_data = cms.EnvelopedData(
        {
            "version": "v0",
            "recipient_infos": [recipient_info],
            "encrypted_content_info": encrypted_content_info,
        }
    )

    # Finally add a wrapper and return its bytes
    content_info = cms.ContentInfo(
        {
            "content_type": "enveloped_data",
            "content": enveloped_data,
        }
    )
    return content_info.dump()
