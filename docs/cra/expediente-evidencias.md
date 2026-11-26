# Expediente de evidencias — ReportAudit 1.0.0

- Repositorio: https://github.com/matteoconcio/reportaudit-lab
- Versión: v1.0.0
- Fecha: 2026-11-26
- Responsable: Matteo Concio

> Índice de evidencias frente a la Cyber Resilience Act (Reglamento (UE) 2024/2847).
> No es una declaración de conformidad: dice qué está demostrado y cómo comprobarlo.

| # | Requisito | Referencia | Evidencia en ReportAudit | Enlace | Cómo lo verifica un tercero |
|---|---|---|---|---|---|
| 1 | Sin vulnerabilidades explotables conocidas al publicar | Anexo I, Parte I, 2.a | Checks SAST y SCA en verde en el commit de v1.0.0; Grype y Trivy «después» a 0; VEX | https://github.com/matteoconcio/reportaudit-lab/actions/workflows/cadena-suministro.yml · [grype-despues.txt](../evidencias/grype-despues.txt) · [VEX](../evidencias/reportaudit.openvex.json) | Abrir el último run de `main` en Actions (4 jobs en verde); `grype sbom:docs/evidencias/sbom-despues.cyclonedx.json` → «No vulnerabilities found» |
| 2 | Configuración segura por defecto | Anexo I, Parte I, 2.b | PR de auditoría: `yaml.safe_load`, consulta parametrizada, sin shell; servicio con `debug=False`; hallazgos restantes revisados en SonarQube | https://github.com/matteoconcio/reportaudit-lab/pull/19 | `grep -n -e safe_load -e debug=False -e shell app/*.py`; SonarQube Cloud → Issues (main): 0 de seguridad |
| 3 | Protección frente a accesos no autorizados | Anexo I, Parte I, 2.d | Credenciales en variables de entorno; regla propia de Gitleaks y baseline; push protection activada | https://github.com/matteoconcio/reportaudit-lab/pull/21 · [.gitleaks.toml](../../.gitleaks.toml) | `gitleaks git . -c .gitleaks.toml --redact` → «no leaks found»; `grep -n "os.environ" app/reporte_auditoria.py` |
| 4 | Identificar y documentar los componentes (SBOM) | Anexo I, Parte II, 1 | SBOM CycloneDX atestado en la Release v1.0.0 | https://github.com/matteoconcio/reportaudit-lab/releases/tag/v1.0.0 | `gh release download v1.0.0 --repo matteoconcio/reportaudit-lab` y `gh attestation verify reportaudit-1.0.0.tar.gz --repo matteoconcio/reportaudit-lab --predicate-type https://cyclonedx.org/bom` |
| 5 | Corregir las vulnerabilidades sin demora | Anexo I, Parte II, 2 | Dependabot activo (#17); PR de dependencias fusionado (#20); puerta SCA obligatoria (#23) que bloqueó el PR de prueba (#24) | https://github.com/matteoconcio/reportaudit-lab/pull/20 · https://github.com/matteoconcio/reportaudit-lab/pull/24 | Security → Dependabot: 0 abiertas; abrir el PR #24 (cerrado sin fusionar) y ver «SCA - pip-audit» en rojo |
| 6 | Pruebas y revisiones periódicas | Anexo I, Parte II, 3 | Pipeline de 4 checks en cada PR; Scorecard semanal (lunes) | https://github.com/matteoconcio/reportaudit-lab/actions/workflows/scorecard.yml · https://scorecard.dev/viewer/?uri=github.com/matteoconcio/reportaudit-lab | Ver en Actions los runs programados de Scorecard y su puntuación pública en scorecard.dev |
| 7 | Información sobre vulnerabilidades corregidas | Anexo I, Parte II, 4 | Borrador de aviso del simulacro GHSA-cvmm-mxqm-7ch3 (en un caso real se publicaría con la versión corregida) | https://github.com/matteoconcio/reportaudit-lab/security/advisories/GHSA-cvmm-mxqm-7ch3 (visible solo para colaboradores) | Un colaborador abre Security → Advisories y comprueba CWE-89, CVSS 7.5, versiones < 1.0.0 / 1.0.0 y créditos |
| 8 | Política de divulgación coordinada | Anexo I, Parte II, 5 | SECURITY.md y canal privado de vulnerabilidades activado | https://github.com/matteoconcio/reportaudit-lab/security/policy | Abrir Security → Policy; comprobar que existe el botón «Report a vulnerability» |
| 9 | Dirección de contacto para vulnerabilidades | Anexo I, Parte II, 6 | SECURITY.md → «Reporting a vulnerability» | https://github.com/matteoconcio/reportaudit-lab/blob/main/SECURITY.md | Seguir el enlace `security/advisories/new` de SECURITY.md (abre el formulario privado) |
| 10 | Distribución segura de las actualizaciones | Anexo I, Parte II, 7 | Release firmada: SHA256SUMS y procedencia Sigstore (SLSA Build L2) | https://github.com/matteoconcio/reportaudit-lab/releases/tag/v1.0.0 · https://github.com/matteoconcio/reportaudit-lab/attestations | `sha256sum -c SHA256SUMS`; `gh attestation verify reportaudit-1.0.0.tar.gz --repo matteoconcio/reportaudit-lab`; una copia alterada falla |
| 11 | Período de soporte declarado | Art. 13.8 | SECURITY.md → Supported versions: 1.x hasta 2031-11-30 (5 años desde 1.0.0) | https://github.com/matteoconcio/reportaudit-lab/blob/main/SECURITY.md#supported-versions | Leer la tabla «Supported versions» y comparar la fecha con la de la Release v1.0.0 |
| 12 | Trazabilidad: cada cambio nace en un Issue y entra por un PR revisado | Buena práctica (no es un requisito literal) | Milestone «Lab 1 - Secure supply chain» con sus Issues cerrados; PRs aprobados; main protegida con 4 checks | https://github.com/matteoconcio/reportaudit-lab/milestone/1?closed=1 · https://github.com/matteoconcio/reportaudit-lab/pulls?q=is%3Apr+is%3Aclosed | Abrir el milestone y cada Issue: enlaza a su PR; en cada PR, ver la aprobación y los checks |

## Lo que este expediente todavía no incluye
La evaluación de riesgos documentada, la documentación técnica completa del Anexo VII, la declaración UE de conformidad y el marcado CE. Los estudiaste en la Práctica 2.
