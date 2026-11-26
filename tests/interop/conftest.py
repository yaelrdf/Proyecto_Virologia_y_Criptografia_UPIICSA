import os
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPO = HERE.parent.parent


@pytest.fixture(scope="session")
def fixtures_dir() -> pathlib.Path:
    """Carpeta con los artefactos que genera `dotnet test` (CC_INTEROP_DIR o artifacts/interop)."""
    path = pathlib.Path(os.environ.get("CC_INTEROP_DIR", REPO / "artifacts" / "interop"))
    if not (path / "certificado.pem").exists():
        pytest.fail(f"No hay artefactos de .NET en {path}. Ejecuta primero `dotnet test CentroCiber.slnx`.")
    return path


@pytest.fixture(scope="session")
def vectors_dir() -> pathlib.Path:
    return REPO / "vectores" / "EQ08"
