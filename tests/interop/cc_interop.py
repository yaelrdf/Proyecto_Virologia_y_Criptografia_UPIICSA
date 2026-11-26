"""Implementación independiente (Python + cryptography) de las primitivas del
Estándar de Comunicación v2.0, usada para verificar lo que produce el nodo EQ08 (.NET).

No comparte código con la implementación .NET: se escribió a partir del estándar.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

PACKAGE_ENTRIES = {"datos.enc", "certificado.pem", "manifest.json"}
RESULT_ENTRIES = {"resultado.enc", "certificado.pem", "manifest.json"}
REQUIRED_FIELDS = [
    "version", "packetType", "packetId", "requestId", "sourceNode", "sourceTeam", "sourceIp",
    "producerNode", "timestampUtc", "algorithmId", "algorithmCode", "algorithmName", "operation",
    "operationName", "payloadMode", "originalFileName", "originalExtension", "originalSizeBytes",
    "contentType", "encryptedSha256", "encryptedSizeBytes", "parts", "keyRef", "publicParameters",
    "publicParametersSha256", "certificateThumbprintSha256", "signatureAlgorithm", "manifestSignatureBase64",
]
ALGORITHMS = {
    1: "AESGCM", 2: "DES", 3: "TRIPLEDES", 4: "CHACHA20", 5: "RSA", 6: "ECC", 7: "DIFFIEHELLMAN",
    8: "CAESAR", 9: "VIGENERE", 10: "XORASM", 11: "LSBSTEGO", 12: "EUCLIDESAFFINE", 13: "MILLERRABIN",
    14: "FISHERYATES", 15: "HASHSHA", 16: "HMACSHA256", 17: "DIGITALSIG", 18: "QUANTUMPQC",
    19: "DFTSPECTRAL", 20: "LAGRANGESHAMIR", 21: "LORENZSZ40",
}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
NODE_RE = re.compile(r"^EQ[0-9]{2}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
THUMB_RE = re.compile(r"^[0-9A-F]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(Exception):
    """Error con el código del Anexo B."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --- §8.1 / §3 -----------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def thumbprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()


# --- §8.5 ------------------------------------------------------------------------

def canonical_text(params: dict) -> str:
    for k, v in params.items():
        if not isinstance(v, str):
            raise ValidationError("E-MANIFEST", f"publicParameters.{k} no es cadena")
    keys = sorted(params.keys(), key=lambda k: k.encode("utf-8"))
    return "\n".join(f"{k}={params[k]}" for k in keys)


def canonical_hash(params: dict) -> str:
    return sha256_hex(canonical_text(params).encode("utf-8"))


# --- §8.4 ------------------------------------------------------------------------

def signature_chain(m: dict) -> str:
    fields = ["version", "packetType", "packetId", "sourceNode", "producerNode", "algorithmCode", "operation",
              "timestampUtc", "encryptedSha256", "publicParametersSha256", "certificateThumbprintSha256"]
    return "|".join(str(m[f]) for f in fields)


# --- §8.2 ------------------------------------------------------------------------

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def verify_pss(cert: x509.Certificate, data: bytes, signature_b64: str) -> bool:
    try:
        cert.public_key().verify(base64.b64decode(signature_b64, validate=True), data, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_pss(private_key: rsa.RSAPrivateKey, data: bytes) -> str:
    return base64.b64encode(private_key.sign(data, PSS, hashes.SHA256())).decode()


# --- §8.3 ------------------------------------------------------------------------

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def seal_envelope(plaintext: bytes, cert: x509.Certificate, recipient_node: str, aad_id: str,
                  include_ciphertext: bool = True) -> tuple[dict, bytes]:
    cek = os.urandom(32)
    nonce = os.urandom(12)
    out = AESGCM(cek).encrypt(nonce, plaintext, aad_id.encode("utf-8"))
    ciphertext, tag = out[:-16], out[-16:]
    env = {
        "envelope": "CC-ENV-1",
        "recipientNode": recipient_node,
        "recipientThumbprintSha256": thumbprint(cert),
        "wrappedKeyBase64": base64.b64encode(cert.public_key().encrypt(cek, OAEP)).decode(),
        "nonceBase64": base64.b64encode(nonce).decode(),
        "tagBase64": base64.b64encode(tag).decode(),
    }
    if include_ciphertext:
        env["ciphertextBase64"] = base64.b64encode(ciphertext).decode()
    return env, ciphertext


def open_envelope(env: dict, private_key: rsa.RSAPrivateKey, my_thumbprint: str, aad_id: str,
                  ciphertext: bytes | None = None) -> bytes:
    if env.get("envelope") != "CC-ENV-1":
        raise ValidationError("E-ENV-DECRYPT", "tipo de sobre desconocido")
    if env.get("recipientThumbprintSha256") != my_thumbprint:
        raise ValidationError("E-ENV-RECIPIENT", "el sobre no es para esta llave")
    if ciphertext is None:
        ciphertext = base64.b64decode(env["ciphertextBase64"])
    nonce = base64.b64decode(env["nonceBase64"])
    tag = base64.b64decode(env["tagBase64"])
    if len(nonce) != 12 or len(tag) != 16:
        raise ValidationError("E-ENV-DECRYPT", "nonce o tag con longitud inválida")
    cek = private_key.decrypt(base64.b64decode(env["wrappedKeyBase64"]), OAEP)
    try:
        return AESGCM(cek).decrypt(nonce, ciphertext + tag, aad_id.encode("utf-8"))
    except InvalidTag as exc:
        raise ValidationError("E-ENV-DECRYPT", "etiqueta GCM inválida") from exc


# --- §7 --------------------------------------------------------------------------

def load_cert(pem: bytes) -> x509.Certificate:
    if pem.count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise ValidationError("E-CERT", "certificado.pem debe tener exactamente un certificado")
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise ValidationError("E-CERT", "PEM inválido") from exc


def check_cert(cert: x509.Certificate, expected_cn: str, now: dt.datetime | None = None) -> None:
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise ValidationError("E-CERT", "la llave no es RSA-2048")
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) != 1 or cns[0].value != expected_cn:
        raise ValidationError("E-CERT", f"CN distinto de {expected_cn}")
    if now is not None and not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValidationError("E-CERT", "certificado fuera de vigencia")


# --- §9 / §13.1 -----------------------------------------------------------------

@dataclass
class PackageReport:
    manifest: dict
    payload: bytes
    certificate: x509.Certificate
    checks: list[str] = field(default_factory=list)


def _bad_name(name: str) -> bool:
    return "/" in name or "\\" in name or ".." in name or name.startswith(".") or name.endswith("/")


def verify_package(zip_bytes: bytes, now: dt.datetime | None = None, check_time: bool = False) -> PackageReport:
    checks: list[str] = []
    if len(zip_bytes) > 50 * 1024 * 1024:
        raise ValidationError("E-SIZE", "más de 50 MB")
    checks.append("#1 tamaño ≤ 50 MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise ValidationError("E-ZIP-INVALID", "no es zip") from exc
    checks.append("#2 zip válido")
    names = {i.filename for i in infos}
    if len(infos) != 3 or any(_bad_name(i.filename) for i in infos) or names not in (PACKAGE_ENTRIES, RESULT_ENTRIES):
        raise ValidationError("E-ZIP-STRUCTURE", f"entradas inválidas: {sorted(names)}")
    checks.append("#3 estructura de 3 archivos")
    total = sum(i.file_size for i in infos)
    compressed = sum(i.compress_size for i in infos)
    if total > 200 * 1024 * 1024 or (compressed > 0 and total / compressed > 100):
        raise ValidationError("E-ZIP-BOMB", "descompresión excesiva")
    checks.append("#4 sin zip-bomb")
    try:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("E-MANIFEST", "manifest.json no es JSON") from exc
    missing = [f for f in REQUIRED_FIELDS if f not in manifest]
    if missing:
        raise ValidationError("E-MANIFEST", f"faltan campos: {missing}")
    if manifest["packetType"] == "result":
        for f in ("verification", "resultEnvelope"):
            if f not in manifest:
                raise ValidationError("E-MANIFEST", f"falta {f}")
    fmt_ok = (UUID_RE.match(manifest["packetId"]) and NODE_RE.match(manifest["sourceNode"])
              and NODE_RE.match(manifest["producerNode"]) and TS_RE.match(manifest["timestampUtc"])
              and THUMB_RE.match(manifest["certificateThumbprintSha256"]) and HASH_RE.match(manifest["encryptedSha256"])
              and HASH_RE.match(manifest["publicParametersSha256"]) and manifest["operation"] in ("forward", "inverse")
              and manifest["packetType"] in ("package", "result")
              and manifest["signatureAlgorithm"] == "RSA-PSS-SHA256"
              and (manifest["requestId"] is None or UUID_RE.match(manifest["requestId"])))
    if not fmt_ok or not isinstance(manifest["publicParameters"], dict):
        raise ValidationError("E-MANIFEST", "formatos de la sección 3 inválidos")
    data_name = "resultado.enc" if manifest["packetType"] == "result" else "datos.enc"
    if data_name not in names:
        raise ValidationError("E-MANIFEST", "packetType no coincide con las entradas")
    checks.append("#5 manifiesto completo")
    if manifest["version"] != "2.0":
        raise ValidationError("E-VERSION", manifest["version"])
    checks.append("#6 versión 2.0")
    if ALGORITHMS.get(manifest["algorithmId"]) != manifest["algorithmCode"]:
        raise ValidationError("E-ALGORITHM", "algorithmId/algorithmCode inconsistentes")
    checks.append("#7 algoritmo de la tabla 4.1")
    payload = zf.read(data_name)
    if sha256_hex(payload) != manifest["encryptedSha256"]:
        raise ValidationError("E-HASH", f"SHA-256 de {data_name}")
    if manifest["payloadMode"] == "multipart":
        inner = zipfile.ZipFile(io.BytesIO(payload))
        by_name = {i.filename: i for i in inner.infolist()}
        for part in manifest["parts"] or []:
            if part["name"] not in by_name or sha256_hex(inner.read(part["name"])) != part["sha256"]:
                raise ValidationError("E-HASH", f"parte {part['name']}")
    checks.append("#8 encryptedSha256")
    if canonical_hash(manifest["publicParameters"]) != manifest["publicParametersSha256"]:
        raise ValidationError("E-PARAMS-HASH", "hash canónico")
    checks.append("#9 publicParametersSha256")
    cert = load_cert(zf.read("certificado.pem"))
    check_cert(cert, manifest["sourceNode"], now or dt.datetime.now(dt.timezone.utc))
    checks.append("#10 certificado RSA-2048, CN, vigente")
    if thumbprint(cert) != manifest["certificateThumbprintSha256"]:
        raise ValidationError("E-CERT-THUMBPRINT", "huella")
    checks.append("#11 huella")
    if not verify_pss(cert, signature_chain(manifest).encode("utf-8"), manifest["manifestSignatureBase64"]):
        raise ValidationError("E-SIGNATURE", "firma RSA-PSS")
    checks.append("#12 firma RSA-PSS-SHA256")
    if check_time:
        ts = dt.datetime.strptime(manifest["timestampUtc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        if abs((ts - (now or dt.datetime.now(dt.timezone.utc))).total_seconds()) > 600:
            raise ValidationError("E-TIMESTAMP", "fuera de ±10 min")
        checks.append("#13 timestamp")
    return PackageReport(manifest=manifest, payload=payload, certificate=cert, checks=checks)


def expected_zip_name(m: dict) -> str:
    stamp = m["timestampUtc"].replace("-", "").replace(":", "").replace("T", "_").rstrip("Z")
    base = f"{m['sourceNode']}_{m['algorithmCode']}_{stamp}_{m['encryptedSha256'][:8].upper()}.zip"
    return ("RES_" + base) if m["packetType"] == "result" else base


def load_private_key(pem: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key
