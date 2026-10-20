# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Make a new operator token, save it to ~/.config/roost/operator-token (mode
600) and print its hex SHA-256 on stdout, for piping into
`pywrangler secret put ROOKERY_OPERATOR_TOKEN_SHA256` (`pixi run cf-operator-token`).
The token itself never goes to stdout or the Worker.
"""

import hashlib
import os
import secrets
import sys
from pathlib import Path

TOKEN_FILE = Path.home() / ".config" / "roost" / "operator-token"


def main() -> None:
    token = secrets.token_urlsafe(32)
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(token)
    print(f"saved a new operator token to {TOKEN_FILE}", file=sys.stderr)
    print(hashlib.sha256(token.encode()).hexdigest(), end="")


if __name__ == "__main__":
    main()
