"""Comprueba que el entorno de interoperabilidad tiene la librería independiente."""

import cryptography


def test_cryptography_available():
    major = int(cryptography.__version__.split(".")[0])
    assert major >= 42
