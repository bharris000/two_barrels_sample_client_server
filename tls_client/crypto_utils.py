import hashlib
import hmac
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def encrypt_with_public_key(public_key, plaintext):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_with_private_key(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def load_certificate(cert_bytes):
    return x509.load_pem_x509_certificate(cert_bytes)


def load_key(key_bytes):
    return load_pem_private_key(key_bytes, password=None)


def mac(data, key):
    return hmac.digest(key, data, "sha256")


def encrypt(plaintext, key):
    iv = os.urandom(16)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv + ciphertext


def decrypt(ciphertext, key):
    iv, ciphertext = ciphertext[:16], ciphertext[16:]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def generate_keys(client_nonce, server_nonce):
    if len(client_nonce) != 32 or len(server_nonce) != 32:
        raise ValueError("Nonces must be 32 bytes long.")

    key = hashlib.pbkdf2_hmac(
        "sha256", client_nonce, server_nonce, 500000, dklen=32 * 4
    )
    return key[0:32], key[32:64], key[64:96], key[96:128]
