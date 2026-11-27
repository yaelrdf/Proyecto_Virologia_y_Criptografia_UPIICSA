"""Verifica con Python las primitivas generadas por .NET (§7, §8)."""

import base64
import json

from cryptography.hazmat.primitives import serialization

import cc_interop


def _cert(d):
    return cc_interop.load_cert((d / "certificado.pem").read_bytes())


def test_certificate_section_7(fixtures_dir):
    cert = _cert(fixtures_dir)
    cc_interop.check_cert(cert, "EQ08")
    assert cert.subject.rfc4514_string() == "CN=EQ08,OU=Equipo 08,O=Centro de Ciberseguridad,C=MX"
    assert cert.issuer == cert.subject
    assert cert.signature_hash_algorithm.name == "sha256"
    assert cert.serial_number.bit_length() >= 64
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days >= 365
    assert cc_interop.thumbprint(cert) == (fixtures_dir / "huella.txt").read_text().strip()


def test_signature_from_dotnet_verifies(fixtures_dir):
    chain = (fixtures_dir / "cadena-firma.txt").read_bytes()
    sig = (fixtures_dir / "firma.b64").read_text().strip()
    assert cc_interop.verify_pss(_cert(fixtures_dir), chain, sig)
    assert not cc_interop.verify_pss(_cert(fixtures_dir), chain + b"x", sig)


def test_canonical_hash_matches_dotnet(fixtures_dir):
    params = json.loads((fixtures_dir / "params.json").read_text(encoding="utf-8"))
    expected_text = (fixtures_dir / "params-canonicos.txt").read_text(encoding="utf-8")
    assert cc_interop.canonical_text(params) == expected_text
    assert cc_interop.canonical_hash(params) == (fixtures_dir / "params-hash.txt").read_text().strip()
    assert cc_interop.canonical_hash({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_envelope_from_dotnet_opens(fixtures_dir):
    env = json.loads((fixtures_dir / "sobre.json").read_text())
    key = cc_interop.load_private_key((fixtures_dir / "privada-PRUEBA.pem").read_bytes())
    aad = (fixtures_dir / "sobre-aad.txt").read_text().strip()
    plain = cc_interop.open_envelope(env, key, cc_interop.thumbprint(_cert(fixtures_dir)), aad)
    assert plain == (fixtures_dir / "sobre-esperado.txt").read_bytes()
    assert len(base64.b64decode(env["nonceBase64"])) == 12
    assert len(base64.b64decode(env["tagBase64"])) == 16


def test_private_key_matches_certificate(fixtures_dir):
    key = cc_interop.load_private_key((fixtures_dir / "privada-PRUEBA.pem").read_bytes())
    pub = _cert(fixtures_dir).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == pub
