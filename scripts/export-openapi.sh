#!/usr/bin/env bash
# Regenera docs/api/openapi.json a partir de la API real (prueba Openapi_document_is_up_to_date).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC_UPDATE_OPENAPI=1 dotnet test "$ROOT/tests/CentroCiber.Api.Tests" --filter "FullyQualifiedName~Openapi" --nologo -v q
echo "docs/api/openapi.json actualizado."
