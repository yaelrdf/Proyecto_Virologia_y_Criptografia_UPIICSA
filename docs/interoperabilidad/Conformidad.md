# Lista de conformidad mínima (§16.2)

Cada punto se marca solo con evidencia **ejecutada**. Lo que depende de otros equipos o de una LAN real queda pendiente, con el motivo.

| # | Requisito §16.2 | Estado | Evidencia |
| --- | --- | :---: | --- |
| 1 | Responde `GET /api/status`, `/api/certificate` y `/api/algorithms` en `5000 + n` | ✅ | `ProviderApiTests.Status_includes_algorithms_https_and_thumbprint`, `Certificate_is_single_pem`, `Algorithms_profile_matches_standard_example`; binario publicado `linux-x64` respondiendo en 5008 |
| 2 | Emite el anuncio UDP cada 30 s y detecta los anuncios de otros | ✅ (loopback y broadcast en una máquina) · 🖐 LAN real | `DirectoryAndDiscoveryTests.Two_nodes_discover_each_other_over_udp_and_tofu`; `scripts/run-two-nodes.sh` con broadcast `255.255.255.255:5099`, donde ambos nodos se registraron como `beacon` |
| 3 | Escaneo HTTP de respaldo y alta manual funcionan | ✅ | `Scan_finds_node_on_port_range`, `Manual_add_verifies_status_and_certificate`, `Automatic_scan_is_throttled` |
| 4 | Genera un certificado RSA-2048 autofirmado con CN = `nodeId` | ✅ | `IdentityTests.Generated_certificate_follows_section_7`; verificado también en Python (`test_certificate_section_7`) |
| 5 | Valida correctamente los vectores 16.1 de los demás equipos | ⏳ | Herramienta lista (`verify_package.py`, `VectorsTests`); los otros equipos aún no publican vectores |
| 6 | Rechaza: zip con 4 archivos, hash alterado, firma alterada, timestamp viejo y `packetId` repetido, con el código correcto | ✅ | `PackageTests.E_ZIP_STRUCTURE_four_files`, `E_HASH_tampered_data`, `E_SIGNATURE_tampered_signature`, `E_TIMESTAMP_old`, `E_DUPLICATE_packet_id`; por API: `InboxApiTests` |
| 7 | `forward` e `inverse` remotos funcionan para cada algoritmo propio | ✅ | `ProviderApiTests` (HASHSHA, HMACSHA256) y `EndToEndTests` (EQ09 → EQ08 por HTTPS) |
| 8 | Puede delegar al menos un algoritmo de cada otro equipo | ✅ contra el nodo simulado · ⏳ equipos reales | `DelegationTests` contra `MockNode` (EQ01/AESGCM, síncrono y `202`); el cliente es genérico para los 19 algoritmos |
| 9 | Sobre `CC-ENV-1` interoperable en ambos sentidos | ✅ (con Python `cryptography`) · ⏳ con otros equipos | `InteropBridgeTests.Python_verifies_artifacts_produced_by_dotnet` y `Dotnet_opens_envelope_created_by_python` |

Vectores propios publicados: [`vectores/EQ08/`](../../vectores/EQ08/README.md), verificados por `VectorsTests` (.NET) y `test_vectors.py` (Python).
