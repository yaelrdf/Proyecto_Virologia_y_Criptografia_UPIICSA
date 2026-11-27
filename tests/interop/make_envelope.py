#!/usr/bin/env python3
"""Crea un sobre CC-ENV-1 con la librería `cryptography` para que .NET lo abra.

Uso: python3 make_envelope.py <certificado.pem> <nodeId> <aad> <archivo_entrada> <salida.json>
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import cc_interop  # noqa: E402


def main() -> int:
    cert_path, node, aad, src, out = sys.argv[1:6]
    cert = cc_interop.load_cert(pathlib.Path(cert_path).read_bytes())
    env, _ = cc_interop.seal_envelope(pathlib.Path(src).read_bytes(), cert, node, aad)
    pathlib.Path(out).write_text(json.dumps(env), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
