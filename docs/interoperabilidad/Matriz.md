# Matriz de interoperabilidad (§16.3)

Combinaciones probadas por EQ08: solicitante × algoritmo × operación. Solo se anotan **pruebas ejecutadas**; lo que falta se marca como pendiente.

Leyenda: ✅ funciona · ❌ falla (con código) · ⏳ pendiente · — no aplica.

## Pruebas automatizadas en el entorno de desarrollo (Linux, 2026-11-26)

Se ejecutan con `dotnet test`. La CI las corre también en Windows.

| Fecha | Solicitante | Proveedor | Algoritmo | `forward` | `inverse` | Bandeja | Evidencia |
| --- | --- | --- | --- | :---: | :---: | :---: | --- |
| 2026-11-26 | EQ03 (cliente de prueba) | EQ08 | HASHSHA | ✅ | ✅ | — | `ProviderApiTests.Forward_HASHSHA_returns_signed_package`, `Inverse_HASHSHA_of_foreign_package` |
| 2026-11-26 | EQ03 (cliente de prueba) | EQ08 | HMACSHA256 | ✅ | ✅ | — | `ProviderApiTests.Forward_and_inverse_HMAC_with_envelope` |
| 2026-11-26 | EQ08 | EQ01 **simulado** (`MockNode`) | AESGCM | ✅ | ✅ | — | `DelegationTests.Delegated_AESGCM_round_trip_with_mock_EQ01` (síncrono y `202`) |
| 2026-11-26 | EQ08 → EQ09 (instancia local) | EQ01 simulado | AESGCM (reenvío) | — | — | ✅ | `DelegationTests.Forward_foreign_package_to_third_party_inbox` |
| 2026-11-26 | EQ09 (instancia local) | EQ08 | HASHSHA | ✅ (EQ08 local) | ✅ (delegado, HTTPS) | ✅ | `EndToEndTests.Two_nodes_exchange_package_end_to_end(HASHSHA)` |
| 2026-11-26 | EQ09 (instancia local) | EQ08 | HMACSHA256 | ✅ (EQ08 local) | ✅ (delegado, HTTPS) | ✅ | `EndToEndTests.Two_nodes_exchange_package_end_to_end(HMACSHA256)` |
| 2026-11-26 | Python `cryptography` | — | Primitivas, paquetes, sobres | — | — | — | `tests/interop` (18 pruebas) |
| 2026-11-27 | EQ08 | EQ01 simulado con variantes (nulos omitidos, sobre en `resultado.enc`, etiqueta pegada) | AESGCM | ✅ | ✅ | — | `DelegationTests.Delegation_tolerates_owner_variants` (ADR 0016/0017) |
| 2026-11-27 | EQ08 → EQ09 → EQ01 simulado | — | AESGCM reenviado | ✅ | ✅ (descifrado por un tercero) | ✅ | `Forwarded_AESGCM_package_can_be_decrypted_by_third_party` (ADR 0015) |

## Prueba integrada con los demás equipos

Se llena durante la sesión con todos los nodos en la misma red (§17).

| Equipo dueño | Algoritmos | EQ08 → dueño `forward` | EQ08 → dueño `inverse` | Dueño → EQ08 (HASHSHA/HMAC) | Bandeja ↔ | Vectores validados | Fecha | Notas |
| --- | --- | :---: | :---: | :---: | :---: | :---: | --- | --- |
| EQ01 | AESGCM, DES | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| EQ02 | TRIPLEDES, CHACHA20 | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| EQ03 | RSA, ECC | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| EQ04 | DIFFIEHELLMAN, CAESAR (por confirmar) | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| EQ05 | VIGENERE, XORASM | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| EQ06 | LSBSTEGO, EUCLIDESAFFINE | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | Compatibilidad revisada con su código, 2026-11-27 ([RelayCryptoNode.md](RelayCryptoNode.md)); falta la prueba real |
| EQ07 | MILLERRABIN, FISHERYATES | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | | |
| — | 17–21 reservados | ⏳ (solo si alguien los anuncia) | ⏳ | — | — | — | | |

## Plataformas

| Escenario | Estado | Evidencia |
| --- | :---: | --- |
| Linux (desarrollo, nube) | ✅ | `dotnet test`: 190 pruebas .NET + 18 de Python |
| Windows (CI `windows-latest`) | ✅ en CI | Workflow `CI`, job «Build y pruebas (windows-latest)» |
| Laptop Windows ↔ laptop Linux en LAN real | ⏳ | Verificación manual pendiente |
