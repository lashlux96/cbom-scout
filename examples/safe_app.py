"""Import-only sample — cbom-scout must report ZERO findings for this file.

This is the false-positive test the whole design is built around: importing
a crypto module is not using it.
"""
import hashlib  # noqa: F401
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401

print("no crypto calls here")
