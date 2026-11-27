"""Verifica los vectores públicos de EQ08 (§16.1) con la implementación independiente en Python."""

import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import zipfile

import cc_interop


def _ts(manifest):
    return dt.datetime.strptime(manifest["timestampUtc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def _verify(vectors_dir, name):
    """Valida con la fecha del propio vector para que la prueba no caduque junto con el certificado."""
    data = (vectors_dir / name).read_bytes()
    m = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    return cc_interop.verify_package(data, now=_ts(m))


def test_vector_files_exist(vectors_dir):
    for f in ["certificado.pem", "privada-PRUEBA.pem", "cadena-firma.txt", "params-canonicos.txt",
              "HASHSHA_ejemplo.zip", "HASHSHA_secretos.json", "HASHSHA_original.txt",
              "HMACSHA256_ejemplo.zip", "HMACSHA256_secretos.json", "HMACSHA256_original.txt"]:
        assert (vectors_dir / f).exists(), f


def test_hashsha_vector(vectors_dir):
    r = _verify(vectors_dir, "HASHSHA_ejemplo.zip")
    original = (vectors_dir / "HASHSHA_original.txt").read_bytes()
    assert r.payload == original
    assert r.manifest["publicParameters"]["digestHex"] == hashlib.sha256(original).hexdigest()
    assert cc_interop.thumbprint(r.certificate) == cc_interop.thumbprint(
        cc_interop.load_cert((vectors_dir / "certificado.pem").read_bytes()))


def test_hmac_vector(vectors_dir):
    r = _verify(vectors_dir, "HMACSHA256_ejemplo.zip")
    original = (vectors_dir / "HMACSHA256_original.txt").read_bytes()
    key = base64.b64decode(json.loads((vectors_dir / "HMACSHA256_secretos.json").read_text())["key"])
    assert len(key) >= 32
    assert r.manifest["publicParameters"]["macHex"] == hmac.new(key, original, hashlib.sha256).hexdigest()


def test_signature_chain_and_canonical_text(vectors_dir):
    r = _verify(vectors_dir, "HASHSHA_ejemplo.zip")
    assert (vectors_dir / "cadena-firma.txt").read_text(encoding="utf-8") == cc_interop.signature_chain(r.manifest)
    text, _, hash_line = (vectors_dir / "params-canonicos.txt").read_text(encoding="utf-8").partition("\n---\n")
    assert text == cc_interop.canonical_text(r.manifest["publicParameters"])
    assert hash_line.strip() == "SHA-256: " + r.manifest["publicParametersSha256"]


def test_result_vector_opens_with_test_key(vectors_dir):
    r = _verify(vectors_dir, "HASHSHA_resultado.zip")
    key = cc_interop.load_private_key((vectors_dir / "privada-PRUEBA.pem").read_bytes())
    m = r.manifest
    plain = cc_interop.open_envelope(m["resultEnvelope"], key, cc_interop.thumbprint(r.certificate), m["packetId"], r.payload)
    assert plain == (vectors_dir / "HASHSHA_original.txt").read_bytes()
    assert m["verification"]["valid"] is True


def test_zip_names_listed(vectors_dir):
    names = json.loads((vectors_dir / "nombres.json").read_text())
    for local, official in names.items():
        m = _verify(vectors_dir, local).manifest
        assert cc_interop.expected_zip_name(m) == official
