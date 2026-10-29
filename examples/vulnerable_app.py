"""Intentionally weak sample — cbom-scout should flag the call sites below."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
digest = hashes.MD5()
cipher = Cipher(algorithms.AES(b"0" * 32), modes.ECB())
