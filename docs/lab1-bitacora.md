# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** MATTEO CONCIO
- **Repositorio:** https://github.com/matteoconcio/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Windows + WSL2 Ubuntu 24.04 LTS, Python 3.12.3
- **Compañero revisor:** ALBERTO CONESA AYALA (@AlbertoConesaAyala2003)

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte C — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | reporte_auditoria.py:41-42 | **Inyección SQL**: la consulta se construye concatenando `nombre_cliente` dentro del texto SQL. Confirmado con `o'brien_ltd` -> `sqlite3.OperationalError` | Parámetro `cliente` de `GET /reportes` (servicio.py:41) | `cursor.execute(query)` (reporte_auditoria.py:42) |
| 2 | `convertir_a_pdf` | reporte_auditoria.py:50-51 | **Inyección de comandos**: el nombre del archivo se concatena en una orden que ejecuta la *shell*; `;`, `&` o `|` permiten encadenar comandos. El `except ValueError` de servicio.py:56 da falsa sensación de validación: la función nunca lanza `ValueError` | Parámetro `archivo` de `GET /convertir` (servicio.py:53) | `os.system(comando)` (reporte_auditoria.py:51) |
| 3 | `cargar_configuracion` | reporte_auditoria.py:33 | **Deserialización YAML insegura**: `yaml.Loader` es el cargador completo, capaz de construir objetos Python arbitrarios (etiquetas `!!python/...`). El comentario muestra que se "arregló" el `TypeError` de PyYAML 6 eligiendo el Loader inseguro en vez de `yaml.safe_load` | Contenido de `app/config.yaml` (servicio.py:22-23) | `yaml.load(f, Loader=yaml.Loader)` (reporte_auditoria.py:33) |
| 4 | `hash_password_legacy` | reporte_auditoria.py:57 | **Hash débil**: MD5 sin sal ni iteraciones. Es rápido de calcular y dos contraseñas iguales dan el mismo hash | Parámetro `password` de la función | `hashlib.md5(...)` (reporte_auditoria.py:57) |
| 5 | Constantes globales (usadas en `notificar_cliente`) | reporte_auditoria.py:21-22 (y 62) | **Secretos en el código**: `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` escritas en claro en un repositorio público; además la línea 62 escribe parte de la clave en el log | El propio código fuente versionado en Git | Cualquiera que lea el repositorio o su historial; salida de log en línea 62 |

**Impacto en elnegocio:**

1. **Inyección SQL:** un atacante podría leer los reportes de auditoría de todos los clientes (por ejemplo con `' OR '1'='1`), rompiendo la confidencialidad entre clientes, y potencialmente alterar la base de datos. Es el hallazgo más grave junto con el 2.
2. **Inyección de comandos:** con `archivo=x; <comando>` cualquiera ejecutaría órdenes en el servidor con los permisos del servicio: robo de `reportes.db`, de credenciales o control total de la máquina.
3. **YAML inseguro:** quien consiga modificar `config.yaml` (despliegue comprometido, acceso a la carpeta) obtendría ejecución de código al arrancar el servicio. Es menos explotable desde fuera que 1 y 2 porque el *source* no es una petición web, pero convierte un fichero de configuración en código ejecutable.
4. **MD5 sin sal:** si se filtra la base de datos del sistema legado, las contraseñas de los clientes se recuperan en segundos con tablas precalculadas, y como la gente reutiliza contraseñas, se exponen también sus otras cuentas. (La función no se llama desde el servicio web, pero el riesgo está en los hashes ya almacenados.)
5. **Secretos expuestos:** al ser el repositorio público, cualquiera puede usar la API de notificaciones en nombre de la empresa y enviar correos desde la cuenta SMTP (p. ej. *phishing* a los clientes con remitente legítimo). Borrar las líneas no basta: siguen en el historial de Git, así que hay que **rotar** ambas credenciales.

---

## SonarQube Cloud
**Organization Key:** matteoconcio
**Project Key:** matteoconcio_reportaudit-lab

## Matriz de detección (se completa a lo largo del laboratorio)

Marca V (lo detectó, anota la regla) o X (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | V | X | X | V python:S3649 (línea 42, Blocker) | V py/sql-injection (línea 42, High) | X | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | V | X | X | V python:S2076 (línea 51, Blocker) | V py/command-line-injection (línea 51, Critical) | X | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | V | X | X | X | X | V python.lang.security.deserialization.avoid-pyyaml-load (línea 33) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | V | V python:S4790 (línea 57) | V python:S4790 (línea 57) | V python:S4790 (línea 57, High) | V py/weak-sensitive-data-hashing (línea 57, High) | V insecure-hash-algorithm-md5 + md5-used-as-password (línea 57) | n/a |
| H5 Clave de API escrita en el código | V | X | X | X | X (indirecto: py/clear-text-logging-sensitive-data, línea 62) | X | X |
| H6 Contraseña SMTP escrita en el código | V | V python:S2068 (línea 22) | V python:S2068 + secrets:S7552 (línea 22) | V secrets:S7552 (línea 22, Blocker) + python:S2068 (línea 22, Medium) | X | X | X |

**Observación Parte E/F (Connected Mode):** al conectar el editor con SonarQube Cloud aparece una regla más sobre la contraseña SMTP (secrets:S7552, del detector de secretos del servidor), pero las inyecciones SQL y de comandos siguen sin marcarse en el editor: el *taint analysis* entre archivos lo calcula el servidor y se ve en SonarQube Cloud, no en el panel Problems. Ni en local ni en la nube aparece la clave de API (H5).

**Observación Parte G (SonarQube Cloud y CodeQL):** Los dos motores en la nube encontraron las dos inyecciones (H1, H2) con *taint analysis* entre `servicio.py` y `reporte_auditoria.py`, que SonarQube for IDE sin conexión no podía calcular, y el MD5 (H4). Ninguno marcó la deserialización YAML (H3): el `Loader=yaml.Loader` explícito no lo reconocen como patrón inseguro. SonarQube Cloud detectó la contraseña SMTP (H6) con dos reglas, pero no la clave de API (H5), porque el nombre `NOTIFICATION_API_KEY` no encaja con sus patrones de secreto. CodeQL no detecta credenciales escritas en el código; solo avisó de forma indirecta de que la clave se escribe en el log (L62, *clear-text logging*). Además, SonarQube marcó un hotspot fuera de mi auditoría manual: CSRF desactivado en `servicio.py` (L25, python:S4502). Conclusión: cada motor ve cosas distintas, y ninguno ve las seis.

**Observación Parte H (Semgrep):** Semgrep (p/python + p/secrets, 188 reglas) bloqueó 3 hallazgos: es la única herramienta que detectó la deserialización YAML insegura (H3), y marcó el MD5 con dos reglas (H4). No detectó las inyecciones SQL ni de comandos (H1, H2): sus reglas comunitarias analizan cada archivo por separado y no siguen el dato desde `servicio.py` hasta el *sink*. Tampoco detectó las credenciales (H5, H6): `p/secrets` solo reconoce formatos conocidos de proveedores, y estas claves son propias de ReportAudit.

**Conclusión de la matriz (Parte L):** ninguna herramienta lo detectó todo. La auditoría manual encontró los 6 hallazgos; la mejor herramienta, SonarQube Cloud, 4 de 6. Cada motor ve cosas distintas porque razona distinto:
- Solo los motores con *taint analysis* entre archivos (SonarQube Cloud y CodeQL) encontraron las inyecciones SQL y de comandos (H1, H2).
- Solo Semgrep encontró la deserialización YAML insegura (H3).
- El MD5 (H4) lo vieron todas las herramientas SAST.
- La clave de API (H5) no la detectó ninguna herramienta: no sigue el formato de ningún proveedor y su nombre no contiene "password". Solo CodeQL avisó, de forma indirecta, de que se escribe en el log.
- La contraseña SMTP (H6) solo la vio SonarQube, por el nombre de la variable; Semgrep (p/secrets) y Trivy, que buscan formatos de proveedor conocidos, no.

Las herramientas encontraron dos cosas que yo no vi en la Parte C: CSRF desactivado en `servicio.py` (SonarQube, python:S4502, L25) y el registro en claro de parte de la clave de API (CodeQL, L62). Y ninguna herramienta SAST ve las 13 vulnerabilidades de las dependencias, que solo aparecen con SCA (Dependabot, Grype, Trivy). Un escaneo limpio de secretos no demuestra que no haya secretos: hacen falta varias capas y el criterio humano.

---

## Parte J — Instalación verificada de Syft, Grype y Trivy

Syft, Grype y Trivy instalados con `scripts/instalar_herramientas.py` en versiones fijas; el instalador comparó el SHA-256 de cada descarga con el publicado y solo instaló tras coincidir. `tools/` está en `.gitignore`: son herramientas de mi equipo, no parte del producto.

| Herramienta | Versión instalada | Integridad SHA-256 |
|---|---|---|
| Syft | 1.52.0 | OK |
| Grype | 0.119.0 | OK |
| Trivy | 0.74.0 | OK |

---

## Parte K — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2: `flask==3.0.0` y `pyyaml==6.0.3` |
| Componentes Python en el SBOM | 9: blinker, click, colorama, flask, itsdangerous, jinja2, markupsafe, pyyaml, werkzeug (2 directas + 7 transitivas) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 de tipo `github-action` (actions/checkout@v6, SonarSource/sonarqube-scan-action@v7, github/codeql-action init y analyze @v4): Syft los lee de `.github/workflows/cadena-suministro.yml`. Las acciones del pipeline también son dependencias de terceros. |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | CycloneDX 1.7 |

**El iceberg:** el equipo eligió 2 dependencias y el producto contiene 9 paquetes Python (×4,5), más 4 acciones del pipeline. Las 13 vulnerabilidades que encontró Grype están en werkzeug y jinja2 (transitivas, `# via flask`) y en flask (directa): 12 de 13 están en paquetes que nadie del equipo eligió.

---

## Parte K — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-34069 / GHSA-2g68-c3qc-8985 | High | 3.0.3 | No: afecta al depurador interactivo y `app/servicio.py` (línea 64) arranca con `debug=False` | Actualizar (PR de Dependabot) + VEX |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49767 / GHSA-q34m-jh98-gwm2 | Medium | 3.0.6 | No: agotamiento al parsear `multipart/form-data`; ReportAudit solo expone GET y lee `request.args`, nunca `request.form`/`files` | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j | Medium | 3.0.6 | No: `safe_join` con rutas UNC solo en Windows con Python < 3.11; corre en Linux con 3.12 y no usa `safe_join` | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2025-66221 / GHSA-hgf8-39gv-g3f2 | Medium | 3.1.4 | No: nombres de dispositivo de Windows en `safe_join`/`send_from_directory`; no se usan y el servicio corre en Linux | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-27199 / GHSA-29vq-49wr-vm6x | Medium | 3.1.6 | No: misma familia (`safe_join` en Windows) | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-21860 / GHSA-87hc-h4r5-73f7 | Medium | 3.1.5 | No: misma familia (`safe_join` en Windows) | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-102598 / GHSA-g6x2-hccm-hh4m | Medium | 3.1.9 | No: misma familia (`safe_join` en Windows, NTFS) | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-22195 / GHSA-h5c8-rqwp-cp95 | Medium | 3.1.3 | No: filtro `xmlattr`; ReportAudit no renderiza plantillas, responde con `jsonify` | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-34064 / GHSA-h75v-3vvj-5mfj | Medium | 3.1.4 | No: filtro `xmlattr`; no hay plantillas | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No: escape del *sandbox* vía `str.format`; exige controlar una plantilla y no hay plantillas | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56201 / GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: exige controlar contenido y nombre de una plantilla | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 | Medium | 3.1.6 | No: escape del *sandbox* vía filtro `attr`; no hay plantillas | Actualizar (PR de Dependabot) |
| flask | 3.0.0 | **Directa** (`# via -r requirements.in`) | CVE-2026-27205 / GHSA-68rp-wp8r-4726 | Low | 3.1.3 | No: falta `Vary: Cookie` al acceder a `session`; ReportAudit no usa `session` | Actualizar (PR de Dependabot) |

**Conclusión del triage:** ninguna es explotable hoy porque ReportAudit no usa las funciones afectadas (sin plantillas, sin sesión, sin formularios, sin `safe_join`, depurador apagado). Aun así se actualiza todo: hay versión corregida, el coste es bajo (PR de Dependabot preparado) y basta un cambio futuro (activar `debug`, añadir una plantilla) para que pasen a ser explotables.

**Comparación con Dependabot** (Parte I): pendiente de que Dependabot procese el grafo de dependencias.

**Documento VEX:** [docs/evidencias/reportaudit.openvex.json](evidencias/reportaudit.openvex.json). Declara `not_affected` para CVE-2024-34069 en `pkg:pypi/werkzeug@3.0.1` con justificación `vulnerable_code_not_in_execute_path`: la vulnerabilidad solo afecta al depurador interactivo y ReportAudit arranca con `debug=False` (`app/servicio.py`, línea 64). Se actualiza igualmente con el PR de Dependabot.


---

## Parte L — Trivy: dependencias y secretos

Trivy (`trivy fs --scanners vuln,secret`, salida en [docs/evidencias/trivy-antes.txt](evidencias/trivy-antes.txt)) encontró en `requirements.txt` las mismas 13 vulnerabilidades que Grype (1 HIGH, 11 MEDIUM, 1 LOW), con las mismas versiones corregidas: confirma el resultado por una segunda vía y con otra base de datos. Grype las identifica por GHSA y Trivy por CVE. En secretos no encontró nada: las credenciales de ReportAudit (`NOTIFICATION_API_KEY`, `SMTP_PASSWORD`) no siguen el formato de ningún proveedor conocido. Que un escáner no encuentre secretos no significa que no los haya.


---

## Parte M — Corrección en un Pull Request de auditoría

- **PR de auditoría:** #19 (`fix(security): fix injections, unsafe YAML, weak hash and hard-coded secrets`), cierra el Issue #5. Corrige H1–H6 en `app/reporte_auditoria.py`: consulta parametrizada, `subprocess.run` con lista de argumentos y lista blanca, `yaml.safe_load`, PBKDF2-SHA256 con sal y credenciales leídas de variables de entorno (sin escribirlas en el log).
- **Credenciales a rotar:** `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` siguen en el historial de Git, así que se consideran comprometidas y deben cambiarse en sus proveedores.
- **Revisión de hallazgos restantes en SonarQube Cloud:** CSRF desactivado en `app/servicio.py:25` (python:S4502) marcado como *False positive*: API JSON interna con solo endpoints GET, sin cookies, sesiones ni formularios.
- **Quality Gate de SonarQube Cloud:** Failed únicamente por cobertura de tests (0 % frente al 80 % de "Sonar way"); ReportAudit no tiene tests. No es un check obligatorio en este laboratorio: los umbrales de calidad se tratan en el Tema 3.

- **Issue de mantenibilidad nueva** (`Use concise character class syntax '\w'`, Low) marcada como *False positive*: en Python 3 `\w` también acepta letras Unicode y ampliaría la lista blanca de nombres de archivo; `[A-Za-z0-9_]` la mantiene estrictamente ASCII a propósito.

- **PR #18 de Dependabot (github-actions):** `actions/checkout` v6 → v7 en el workflow; checks en verde, revisado y fusionado. Las acciones del pipeline también son dependencias de terceros y se mantienen actualizadas.

- **PR #20 de Dependabot (pip, grupo parches-de-seguridad):** flask 3.0.0 → 3.1.3, jinja2 3.1.2 → 3.1.6, werkzeug 3.0.1 → 3.1.9 (más blinker e itsdangerous arrastradas por flask). Vinculado al Issue #6 desde Development; revisado, fusionado y entorno actualizado con `pip install -r requirements.txt`.

---

## Parte N — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (YAML L33, MD5 L57 ×2) | 0 (Passed) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 | 0 (4 cerradas como Fixed) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 issues de seguridad (3 Blocker, 2 High, 1 Medium) | 0 |
| Security Hotspots por revisar en SonarQube Cloud | n/a: concepto retirado; ahora son issues | 0 (CSRF revisado como *False positive*) |
| Vulnerabilidades de Grype sobre el SBOM | 13 (1 High, 11 Medium, 1 Low) | 0 |
| Vulnerabilidades de Trivy en `requirements.txt` | 13 | 0 |
| Alertas abiertas de Dependabot | N | 0 |
| Secretos en el historial (Gitleaks con regla propia) | 2 | 0 (2 rotados y registrados en la baseline) |

Evidencias: [SBOM antes](evidencias/sbom.cyclonedx.json) / [después](evidencias/sbom-despues.cyclonedx.json), [Grype antes](evidencias/grype-antes.txt) / [después](evidencias/grype-despues.txt), [Trivy antes](evidencias/trivy-antes.txt) / [después](evidencias/trivy-despues.txt), [VEX](evidencias/reportaudit.openvex.json), [Gitleaks](evidencias/gitleaks-historial.json).

---

## Preguntas de comprobación (Sección 7 de la guía)

1. **Windows, Ubuntu y GitHub.** En Windows viven VS Code, el navegador y el Word de evidencias. En Ubuntu (WSL2) vive todo el proyecto: `~/reportaudit-lab`, Python y el `venv`, Git, Syft, Grype, Trivy, Gitleaks y la base de datos. En GitHub viven la copia pública, los PRs, el pipeline (Actions), los secretos, la protección de main, Dependabot y los resultados de CodeQL; en SonarQube Cloud, el proyecto y el panel de análisis. Se trabaja en Ubuntu porque las herramientas de seguridad y los runners de GitHub Actions son Linux: lo que funciona en mi terminal funciona igual en el pipeline.

2. **Directa y transitiva.** Una dependencia directa es una que el equipo eligió y declaró; una transitiva llega arrastrada por otra. En mi SBOM, `flask` y `pyyaml` son directas (`# via -r requirements.in`), mientras que `werkzeug` (`pkg:pypi/werkzeug@3.0.1`) y `jinja2` son transitivas (`# via flask`). Doce de las trece vulnerabilidades estaban en transitivas que nadie del equipo eligió.

3. **Source y sink.** El *source* es el punto por donde entra un dato controlado por el usuario y el *sink* el punto donde ese dato puede causar daño. Ejemplo real: `request.args.get("cliente")` en `servicio.py` (source) llega sin filtrar a `cursor.execute(query)` en la línea 42 de `reporte_auditoria.py` (sink).

4. **`o'brien_ltd`.** El apóstrofo cerraba la cadena SQL construida por concatenación (`... WHERE cliente = 'o'brien_ltd'`) y la consulta quedaba mal formada (error 500). Si un dato legítimo puede cambiar la estructura de la orden SQL, un dato malicioso puede añadir condiciones u órdenes: los datos se mezclaban con el código, que es la definición de una inyección SQL. Con la consulta parametrizada devuelve 1 reporte.

5. **Hook de Semgrep.** Actúa antes de que el commit exista, en mi equipo, y da la respuesta en segundos; SonarQube Cloud y CodeQL analizan después del push. Además, fue la única herramienta que detectó el YAML inseguro. No basta solo porque vive en la copia local: quien no ejecute `pre-commit install` no lo tiene y se puede saltar con `--no-verify`. Por eso el mismo tipo de análisis es también obligatorio en el pipeline.

6. **No detectaron lo mismo.** No es un error: cada motor razona distinto. SonarQube Cloud y CodeQL hacen *taint analysis* entre archivos y encontraron las inyecciones (H1, H2); Semgrep usa patrones por archivo y fue el único que vio el YAML (H3); SonarQube detecta credenciales por el nombre de la variable (H6) y Trivy, Gitleaks y Semgrep solo por formatos conocidos de proveedor. Ninguna encontró las seis; la matriz demuestra que hacen falta varias capas y el criterio humano.

7. **PR de código y PR de Dependabot.** Son problemas de categorías distintas. Las alertas de CodeQL (SAST) señalan líneas de nuestro código y solo se cierran cuando un nuevo análisis ya no las encuentra, cosa que consiguió el PR #19. Las alertas de Dependabot (SCA) señalan versiones de librerías en `requirements.txt` y solo se cierran al cambiar esas versiones, cosa que consiguió el PR #20. Ninguno de los dos PRs tocaba lo que mira la otra herramienta.

8. **Borrar un secreto frente a corregirlo de verdad.** Borrarlo del código solo evita que siga en las versiones nuevas: el valor sigue en el historial de Git, en GitHub y en cada clon. Corregirlo de verdad es rotarlo (que deje de servir), sacarlo del código hacia variables de entorno o un gestor de secretos, y añadir controles para que no vuelva (regla propia de Gitleaks).

9. **VEX.** Ignorar una alerta la oculta sin dejar rastro, y nadie sabrá después por qué se descartó. Un VEX es un documento revisable que dice qué vulnerabilidad, en qué componente, que no nos afecta, por qué (`justification` estándar) y quién lo decidió y cuándo. El mío declara `not_affected` para CVE-2024-34069 en `pkg:pypi/werkzeug@3.0.1`, con `vulnerable_code_not_in_execute_path`, porque solo afecta al depurador y el servicio arranca con `debug=False` (`servicio.py`, línea 64). Aun así, se actualizó.

10. **Instalador de herramientas.** Fija una versión concreta de cada herramienta, descarga el archivo y la lista oficial de huellas SHA-256 del proyecto, las compara y solo instala si coinciden: detecta una descarga corrupta o alterada por el camino. No puede garantizar que la publicación oficial sea legítima: en el caso Trivy de marzo de 2026 los atacantes comprometieron el propio proyecto y reescribieron sus etiquetas, así que la huella publicada era la del binario malicioso. Por eso se fijan versiones revisadas en lugar de «la última» y los equipos más exigentes verifican además la firma de la publicación.

11. **Gitleaks: código limpio, historial no.** La Parte M sustituyó las credenciales por variables de entorno, así que el código actual no las contiene; pero Git conserva todos los commits y siguen legibles en el commit de importación (3319c72), en GitHub y en cada clon. Lo que cierra el riesgo de verdad es la rotación: que esas credenciales dejen de servir. La regla propia y la baseline impiden que vuelvan a entrar sin silenciar la herramienta.

12. **Por qué pip-audit no se exigió desde la Parte G (ratchet).** En la Parte G las dependencias tenían 13 vulnerabilidades conocidas: con pip-audit obligatorio, ningún PR (ni el de Semgrep, ni el de Dependabot, ni la corrección de seguridad) habría podido fusionarse. El trinquete consiste en llevar primero el sistema al nivel deseado y después prohibir retroceder: en mi repositorio, primero se actualizaron las dependencias (#20) y se registró el historial de secretos (#21), y solo entonces se añadieron pip-audit y Gitleaks como checks obligatorios (#23). Desde ese momento, el PR de prueba #24 con werkzeug 3.0.1 quedó bloqueado.

13. **Alerta de Dependabot vs. check SCA - pip-audit.** La alerta de Dependabot informa de una dependencia vulnerable ya presente en el repositorio y propone un PR con la corrección, pero no impide fusionar nada. El check obligatorio pip-audit actúa en cada PR antes de fusionar: si el cambio introduce o mantiene una versión con vulnerabilidad conocida, el PR no puede entrar en main. Uno avisa y propone; el otro bloquea.

15. **Canal privado y SECURITY.md.** Un Issue es público: describir allí una vulnerabilidad explicaría a cualquiera cómo atacar el producto antes de que exista la versión corregida. El canal privado permite al responsable confirmar el fallo, puntuarlo, preparar la corrección con el investigador y publicar el aviso solo cuando los usuarios pueden actualizar. SECURITY.md es la política pública que dice cómo informar, qué plazos de respuesta y divulgación se comprometen, qué versiones tienen soporte y hasta cuándo, y que no habrá acciones legales contra quien informe de buena fe.

16. **Maintained = 0.** No es un problema de seguridad: Scorecard mide actividad en los últimos 90 días y el repositorio es más joven, así que no tiene datos. Enseña que una métrica sin contexto engaña: la nota global (6.8) baja por checks que describen la edad o el tamaño del equipo, no por vulnerabilidades. Hay que leer el porqué de cada check antes de sacar conclusiones, y usar la nota para priorizar mejoras o comparar dependencias, no como certificación.

17. **Expediente (Parte T) frente a la P2.** En la Práctica 2 (CRA) relacionamos en teoría los requisitos del Anexo I con prácticas y herramientas: SAST y SCA en el pipeline, SBOM, escaneo de secretos, política de divulgación coordinada, actualizaciones firmadas y un período de soporte de 5 años. Ahora casi todo eso existe de verdad y se puede comprobar: checks obligatorios en cada PR (SonarQube Cloud, CodeQL, pip-audit, Gitleaks), SBOM CycloneDX atestado en la Release v1.0.0, procedencia firmada con Sigstore que cualquiera verifica con `gh attestation verify`, SECURITY.md con soporte hasta 2031-11-30, canal privado y un borrador de aviso (GHSA-cvmm-mxqm-7ch3). Lo que sigue sin existir es la parte documental y de gestión: la evaluación de riesgos documentada (Art. 13.2–13.3), la documentación técnica completa del Anexo VII, la declaración UE de conformidad y el marcado CE, y el procedimiento real de notificación del Art. 14 (24 h / 72 h / 14 días). Tampoco hay pruebas de seguridad dinámicas ni fuzzing, como señala Scorecard.




## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #1 | Adopt an international pull request template | #14 |
| #2 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | #15 |
| #3 | Block insecure commits with a Semgrep pre-commit hook | #16 |
| #4 | Enable Dependabot alerts and security updates | #17 + cierre manual tras analizar la primera alerta (I.3) |
| #5 | Remediate the findings of the security audit | #19 |
| #6 | Upgrade the vulnerable dependencies | #20 (PR de Dependabot, vinculado desde Development) |
| #7 | Publish the audit log and the before/after evidence | #22 |
| #8 | Detect ReportAudit credentials in the whole Git history | #21 |
| #9 | Make SCA and secret scanning required checks on main | #23 + PR de prueba #24 (cerrado sin fusionar) + cierre manual tras P.4 |
| #10 | Publish a security policy and a private vulnerability reporting channel | #25 + simulacro GHSA-cvmm-mxqm-7ch3 (borrador, no publicado) + cierre manual |
| #11 | Release v1.0.0 with an SBOM and signed provenance | #26 + Release v1.0.0 + cierre manual tras R.3 |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | #27 |
| #13 | Build the CRA evidence index |  |

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | — |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key`: NOTIFICATION_API_KEY, línea 21; SMTP_PASSWORD no detectada) | 3319c72 (importación) |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`reportaudit-hardcoded-credential`: líneas 21 y 22) | 3319c72 (importación) |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 (2 registradas en la baseline como rotadas) | — |

¿Por qué el código actual está limpio y el historial no? ¿Qué medida de la Parte M cierra el riesgo y cuál no lo cierra?
El código actual está limpio porque la Parte M sustituyó las credenciales por variables de entorno, pero Git conserva todos los commits: las dos credenciales siguen legibles en el commit de importación (3319c72), en GitHub, en cada clon y en cada fork. Sacarlas del código cierra el riesgo de que se sigan usando o copiando desde el código nuevo, pero no el de que alguien las lea en el historial; eso solo lo cierra la rotación (que dejen de servir). La regla propia impide que vuelvan a entrar, y la baseline registra solo esos dos hallazgos concretos, así que cualquier secreto nuevo hará fallar el análisis.

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí (desde G.6) | Verde (el código no cambia) |
| SAST - CodeQL | Sí (desde G.6) | Verde |
| SCA - pip-audit | Sí (desde P.4) | **Rojo**: werkzeug 3.0.1 con vulnerabilidades conocidas; PR cerrado sin fusionar |
| Secretos - Gitleaks | Sí (desde P.4) | Verde |

**Dependabot vs. pip-audit:** una alerta de Dependabot avisa y propone un PR, pero no impide fusionar nada; el check obligatorio SCA - pip-audit convierte "hay una vulnerabilidad conocida" en "este PR no entra en main". **Por qué no se exigió en la Parte G (trinquete):** con las dependencias vulnerables de entonces, ningún PR (ni el de Semgrep ni el de Dependabot) habría podido fusionarse. Primero se llevó el repositorio a un estado limpio (#20) y solo después se prohibió retroceder (#23).

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub): @Liria18
- Identificador del borrador de aviso (GHSA-…): GHSA-cvmm-mxqm-7ch3
- Severidad y vector CVSS: High 7.5 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- CWE: CWE-89 (SQL Injection)
- Versiones afectadas / versión corregida: < 1.0.0 / 1.0.0

**Por qué un canal privado y no un Issue:** un Issue público revelaría cómo atacar ReportAudit antes de que exista la versión corregida. El borrador privado permite confirmar, puntuar y preparar la corrección con el investigador, y publicar el aviso solo cuando los usuarios ya pueden actualizar. La obligación de notificación de la CRA (P2) se activaría si la vulnerabilidad se estuviera explotando activamente; en este simulacro no hay explotación activa y el fallo ya está corregido, así que no se activa.

### R. Versión 1.0.0 verificable

Release: https://github.com/matteoconcio/reportaudit-lab/releases/tag/v1.0.0 (workflow `publicar-version.yml`, PR #26, etiqueta anotada `v1.0.0`).

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | OK para `reportaudit-1.0.0.tar.gz` y `reportaudit-sbom.cdx.json` |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo matteoconcio/reportaudit-lab` | ✓ Verification succeeded (workflow publicar-version.yml, refs/tags/v1.0.0) |
| SBOM atestado | `gh attestation verify … --predicate-type https://cyclonedx.org/bom` | ✓ Verification succeeded |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo …` | ✗ Falla: huella distinta y ninguna atestación para ese archivo |

**Qué ataque detecta cada comprobación:** las huellas detectan una descarga incompleta o corrupta, pero no un atacante que cambie a la vez el archivo y `SHA256SUMS`. La procedencia detecta ese caso, porque la firma Sigstore liga el archivo a mi workflow, mi repositorio y mi etiqueta, y no se puede rehacer sin ellos. El SBOM atestado demuestra que el inventario publicado describe exactamente ese paquete. Ninguna de las tres detectaría código malicioso introducido **antes** de etiquetar (en un PR fusionado o en el propio workflow): eso lo cubren la revisión de PRs, los checks obligatorios y la revisión de los workflows.

**Incidencia:** `gh attestation` no existía en la versión de GitHub CLI de los repositorios de Ubuntu; actualicé `gh` desde el repositorio oficial de GitHub (paquete firmado con su clave GPG).

### S. Madurez (OpenSSF Scorecard)

Informe: https://scorecard.dev/viewer/?uri=github.com/matteoconcio/reportaudit-lab (Scorecard v5.5.0, 26/11/2026). Workflow `scorecard.yml` en main (PR #NN).

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | **6.8** | Media ponderada por riesgo de los checks |
| Maintained | 0 | El repositorio tiene menos de 90 días: Scorecard no puede medir actividad sostenida. No dice nada de la seguridad del código. |
| Pinned-Dependencies | 0 | Las acciones de los workflows se fijan por etiqueta (`@v7`, `@v4`), no por hash de commit; una etiqueta se puede mover a otro código (caso Trivy 2026). Mejora con el reto S.3. |
| Fuzzing | 0 | ReportAudit no tiene pruebas de fuzzing (ni tests en general): fuera del alcance del laboratorio. |
| License | 0 | El repositorio no tiene archivo `LICENSE`. |
| Contributors | 0 | Un solo autor, sin contribuidores de varias organizaciones: es un proyecto académico individual. |
| CII-Best-Practices | 0 | No se ha solicitado la insignia OpenSSF Best Practices. |
| Code-Review | 7 | La mayoría de cambios entraron por PR aprobado, pero cuentan en contra el commit de importación y los dos commits directos del README (ea776b1, 5cb7485). |
| Signed-Releases | 8 | Reconoce las firmas Sigstore de la Release v1.0.0; no llega a 10 porque no identifica un archivo de procedencia SLSA con su formato estándar (`*.intoto.jsonl`). |
| Branch-Protection | ? | Con reglas clásicas, Scorecard necesita un token de administrador para leerlas; la protección existe (4 checks + 1 aprobación + sin bypass). |
| Altas | 10 | Dangerous-Workflow, Token-Permissions, Dependency-Update-Tool, Security-Policy, Vulnerabilities y Binary-Artifacts confirman el trabajo de las Partes G–Q. SAST 9 y CI-Tests 9. |

**Lectura con criterio:** la nota premia prácticas, no mide seguridad real. Los checks que más dicen sobre ReportAudit (Vulnerabilities 10, Token-Permissions 10, Security-Policy 10, SAST 9) están en lo alto. Los ceros que bajan la media (Maintained, Contributors, Fuzzing, CII) describen un proyecto nuevo, individual y académico, no un riesgo concreto.

**Check más útil para elegir una dependencia:** Vulnerabilities (y Dependency-Update-Tool), porque dicen si hoy tiene fallos conocidos sin corregir y si alguien los vigila. **Más engañoso sin contexto:** Maintained, que da 0 a un proyecto nuevo y bien cuidado como ReportAudit, y Contributors, que penaliza a un equipo pequeño aunque revise todo por PR.

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`.

Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora existe de verdad, y cuál sigue sin existir?
