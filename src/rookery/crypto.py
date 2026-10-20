# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The `cryptography` modules, imported on first use.

Python Workers forbid randomness while the module loads (snapshotting), and
importing `cryptography` touches the RNG, so nothing may import it at the top
level. Everything goes through `lib()` instead.
"""

from functools import cache
from types import SimpleNamespace


@cache
def lib() -> SimpleNamespace:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

    return SimpleNamespace(
        InvalidSignature=InvalidSignature, hashes=hashes, serialization=serialization, ec=ec, padding=padding,
        rsa=rsa, decode_dss_signature=decode_dss_signature, encode_dss_signature=encode_dss_signature,
    )
