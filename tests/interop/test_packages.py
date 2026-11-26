"""Verifica con Python los paquetes v2.0 producidos por .NET (§9, §13.1)."""

import hashlib
import hmac
import io
import json
import zipfile

import pytest

import cc_interop

ORIGINAL = "Mensaje de interoperabilidad — EQ08 ✓".encode("utf-8")
HMAC_KEY = bytes(range(32))


def _load(fixtures_dir, name):
    return (fixtures_dir / "paquetes" / name).read_bytes()


def test_hashsha_package(fixtures_dir):
    r = cc_interop.verify_package(_load(fixtures_dir, "hashsha.zip"), check_time=True)
    m = r.manifest
    assert m["algorithmCode"] == "HASHSHA" and m["algorithmId"] == 15
    assert r.payload == ORIGINAL
    assert m["publicParameters"]["digestHex"] == hashlib.sha256(ORIGINAL).hexdigest()
    assert m["operationName"] == "calcular hash"


def test_hmac_package(fixtures_dir):
    r = cc_interop.verify_package(_load(fixtures_dir, "hmacsha256.zip"))
    expected = hmac.new(HMAC_KEY, ORIGINAL, hashlib.sha256).hexdigest()
    assert r.manifest["publicParameters"] == {"macAlgorithm": "HMAC-SHA256", "macHex": expected}
    # La clave nunca aparece en el manifiesto (§9.5)
    assert "key" not in json.dumps(r.manifest["publicParameters"])


def test_result_package_envelope_opens_in_python(fixtures_dir):
    r = cc_interop.verify_package(_load(fixtures_dir, "result.zip"))
    m = r.manifest
    assert m["packetType"] == "result" and m["verification"] == {"valid": True, "detail": "Hash coincide"}
    assert "ciphertextBase64" not in m["resultEnvelope"]
    key = cc_interop.load_private_key((fixtures_dir / "privada-PRUEBA.pem").read_bytes())
    plain = cc_interop.open_envelope(m["resultEnvelope"], key, cc_interop.thumbprint(r.certificate), m["packetId"], r.payload)
    assert plain == ORIGINAL


def test_multipart_package(fixtures_dir):
    r = cc_interop.verify_package(_load(fixtures_dir, "multipart.zip"))
    assert [p["name"] for p in r.manifest["parts"]] == ["part-01.bin", "part-02.bin"]


def test_tampering_is_detected(fixtures_dir):
    data = _load(fixtures_dir, "hashsha.zip")
    zf = zipfile.ZipFile(io.BytesIO(data))
    entries = {i.filename: zf.read(i.filename) for i in zf.infolist()}
    entries["datos.enc"] = b"X" + entries["datos.enc"][1:]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for k, v in entries.items():
            out.writestr(k, v)
    with pytest.raises(cc_interop.ValidationError) as exc:
        cc_interop.verify_package(buf.getvalue())
    assert exc.value.code == "E-HASH"


def test_zip_names_follow_nomenclature(fixtures_dir):
    m = cc_interop.verify_package(_load(fixtures_dir, "result.zip")).manifest
    assert cc_interop.expected_zip_name(m).startswith("RES_EQ08_HASHSHA_")
