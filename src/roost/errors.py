# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""An XRPC error with its lexicon error name and HTTP status, raised anywhere
(including inside a Durable Object) and rendered as the standard envelope."""

from .repo import RepoError


class XrpcError(RepoError):
    def __init__(self, name: str, message: str, status: int = 400):
        super().__init__(message)
        self.name, self.message, self.status = name, message, status
