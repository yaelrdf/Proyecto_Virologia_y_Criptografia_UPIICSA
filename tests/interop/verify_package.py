#!/usr/bin/env python3
"""Verificación independiente de un paquete .zip v2.0.

Uso:
    python3 tests/interop/verify_package.py <zip> [--check-time] [--private-key llave.pem]

Con --private-key se abre además el resultEnvelope de un paquete `result`.
Sale con código 0 si todo es válido; si no, imprime el código E-... y sale con 1.
"""

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import cc_interop  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("zip")
    parser.add_argument("--check-time", action="store_true", help="valida la ventana de ±10 min (§13.1 #13)")
    parser.add_argument("--private-key", help="PEM de la llave privada del destinatario del resultEnvelope")
    args = parser.parse_args()
    data = pathlib.Path(args.zip).read_bytes()
    try:
        report = cc_interop.verify_package(data, check_time=args.check_time)
    except cc_interop.ValidationError as exc:
        print(f"INVÁLIDO {exc.code}: {exc.detail}")
        return 1
    for c in report.checks:
        print(f"  OK {c}")
    m = report.manifest
    name = cc_interop.expected_zip_name(m)
    print(f"  Nombre esperado: {name}" + ("" if pathlib.Path(args.zip).name == name else "  (el archivo tiene otro nombre; es informativo, §9.2)"))
    if args.private_key and m["packetType"] == "result" and m.get("resultEnvelope"):
        key = cc_interop.load_private_key(pathlib.Path(args.private_key).read_bytes())
        my_thumb = m["resultEnvelope"]["recipientThumbprintSha256"]
        plain = cc_interop.open_envelope(m["resultEnvelope"], key, my_thumb, m["packetId"], report.payload)
        print(f"  OK resultEnvelope abierto: {len(plain)} bytes; verification={m.get('verification')}")
    print(f"VÁLIDO {m['sourceNode']} {m['algorithmCode']} {m['operation']} {m['packetId']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
