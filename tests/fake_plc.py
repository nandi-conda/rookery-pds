# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""A PLC directory stand-in: accepts operations and serves the audit log."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from roost import cbor
from roost.cbor import CID


class PlcState:
    def __init__(self):
        self.log: dict[str, list[dict]] = {}

    def submit(self, did: str, op: dict) -> None:
        cid = str(CID.for_cbor(cbor.encode(op)))
        self.log.setdefault(did, []).append({"did": did, "cid": cid, "nullified": False, "operation": op})


def serve(port: int) -> ThreadingHTTPServer:
    state = PlcState()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status: int, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            did = self.path.strip("/")
            op = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.submit(did, op)
            self._send(200, {})

        def do_GET(self):
            parts = self.path.strip("/").split("/")
            if len(parts) == 3 and parts[1:] == ["log", "audit"] and parts[0] in state.log:
                return self._send(200, state.log[parts[0]])
            self._send(404, {"message": "DID not registered"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.state = state
    return server


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8790).serve_forever()
