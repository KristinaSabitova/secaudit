# secaudit — práctica 3: estado, arquitectura y plan

Fecha: 2026-11-02 · versión de la herramienta: 0.4.0 · migración: 0017.

La práctica se hizo en dos partes. La primera (commits `342b1dc` a
`0de86d7`) dejó varias funcionalidades parciales o pendientes. La segunda
(versión 0.4.0, migración `0017`) las implementa; la matriz recoge el estado
tras ambas.

Este documento es el entregable de la práctica: diagnóstico, matriz
funcional, arquitectura, el auditor de seguridad MCP, limitaciones, lo que
queda pendiente y las pruebas realmente ejecutadas. Lo que figura como
**pendiente** no está implementado; lo **parcial** está implementado con los
límites que se indican.

## 1. Diagnóstico de partida

secaudit ya tenía un núcleo sólido (v3, fases 1-9). Ese núcleo se ha
mantenido y validado: los 820 tests previos siguen pasando.

- Una auditoría por modelo en un proceso aislado con el entorno filtrado
  (`web/runner.py`).
- El servidor verifica las citas contra su propio checkout (`analysis/evidence.py`).
- Refutación por grafo de llamadas y saneado (`falsify.py`).
- Comparación de vistas del repositorio (`parallax.py`).
- Memoria inmune con reglas Semgrep validadas (`immune.py`).
- Mapa de palanca (`leverage.py`) y caminos de ataque encadenados (`attacker.py`).
- Señuelos para medir la integridad del auditor (`canary.py`).
- Cobertura por niveles de riesgo (`chunking.py`).

Huecos detectados frente al enunciado:

- Ningún estado de evaluación uniforme (CONFIRMADO / POTENCIAL / DESCARTADO /
  NO VERIFICABLE). Sin cadena de evidencia exportable ni métrica de confianza.
- Sin escáneres deterministas de secretos, dependencias ni MCP; todo dependía
  del modelo.
- Sin SBOM, SARIF ni informe autónomo.
- Sin deriva entre auditorías ni inventario de superficie de ataque.
- Sin allowlist de propietarios de repositorio, y lectura del checkout sin
  límite total.

## 2. Matriz funcional

Estados: **existente** (ya estaba), **nuevo** (implementado en esta
práctica), **parcial**, **pendiente**.

### A. Núcleo (A1-A9)

Todo lo enumerado en el diagnóstico es **existente** y está validado por la
suite completa. Ningún módulo del núcleo ejecuta código del repositorio
auditado. Dos puntos se completan en la segunda parte:

| # | Funcionalidad | Estado | Dónde |
|---|---|---|---|
| A4 | Documentación frente a código | **nuevo** | `analysis/doc_claims.py`: 10 tipos de afirmación (hash de contraseñas, autenticación, rate limiting, CSRF, cifrado en reposo, validación, TLS, MFA, auditoría, debug). Cada una sale respaldada, sin respaldo o contradicha por el código. Si alguna no está respaldada, la confianza lo dice en sus límites. Se muestra en «Parallax» |
| A7 | Caminos hipotéticos frente a sólidos | **nuevo** | Un paso es sólido solo si el hallazgo está CONFIRMADO; si no, es tentativo y el camino se marca «hipotético» en la UI y en el gemelo digital |

### B. Ampliaciones

| # | Funcionalidad | Estado | Dónde |
|---|---|---|---|
| B10 | Dependencias, SBOM, OSV y mantenimiento | **nuevo** | `analysis/deps.py`: PyPI, npm, Go, crates.io, RubyGems, Packagist y Maven/Gradle (`pom.xml` con propiedades literales del mismo pom y `dependencyManagement`; `build.gradle(.kts)` leído como texto, nunca evaluado; catálogos `libs.versions.toml`; `gradle.lockfile`); CycloneDX 1.5 en `/sbom.cdx.json`. OSV con `SECAUDIT_OSV_CHECK=1`. Paquetes abandonados (sin release en 730 días) y deprecados con `SECAUDIT_ABANDONED_CHECK=1` (PyPI, npm, crates.io). La UI dice si solo hay dependencias directas por falta de lockfile |
| B11 | Taint | **nuevo** (con límites) | `analysis/taint.py`. Python con ast, entre funciones del mismo fichero (hasta tres llamadas de profundidad, con resúmenes por función): de `request.*`, `sys.argv`, `input()` y parámetros de rutas hasta SQL, shell, eval, rutas, SSRF, plantillas, deserialización, redirecciones y respuestas, cortado por saneadores conocidos. JS/TS sobre árbol sintáctico con tree-sitter (`analysis/taint_js.py`, dependencia opcional fijada): cierres de callbacks, funciones auxiliares del mismo fichero, desestructuración, parámetros de petición y respuesta renombrados, `$where` de MongoDB. Sin tree-sitter vuelve a leer JS por patrón. Cada hallazgo guarda el flujo paso a paso y queda POTENCIAL |
| B12 | Prompt injection | **existente + nuevo** | Instrucciones ocultas en ficheros de agente (`parallax.py`); envenenamiento de herramientas MCP (MCP03, MCP06) |
| B13 | Impacto | **existente** | `leverage.py`, `attacker.py` |
| B14 | Diferencial de PR y commits | **nuevo** | `analysis/drift.py`: hallazgos nuevos, corregidos, persistentes y reintroducidos. Se compara con la auditoría anterior, con una base elegida (`base_ref`, rama o commit) o, para un pull request, con su base. El webhook atiende `pull_request` (opened, synchronize, reopened) y audita el commit de cabeza; un fork fuera de la allowlist se ignora. Opcional (`SECAUDIT_PR_COMMENTS` y un token de escritura aparte): un comentario en el PR, editado en cada push, y un estado `secaudit` en el commit (`web/prnotify.py`). En modo `summary` solo recuentos y enlace; en `full`, también título y fichero:línea de cada hallazgo nuevo, nunca fragmentos de código |
| B15 | Informes PDF / JSON / SARIF | **nuevo** | `analysis/reports.py` y `analysis/pdf.py`: un escritor PDF 1.4 propio, sin dependencias, sin scripts ni enlaces, en `/report.pdf` |
| B16 | Trust Score | **nuevo** | `analysis/trust.py`: tres dimensiones separadas (cobertura, evidencia, resistencia adversarial), sin nota global a propósito |
| B17 | Detección de secretos | **nuevo** | `analysis/secrets_scan.py`, con valores siempre enmascarados `[REDACTED:<hash>]` |
| B18 | Reproducibilidad | **nuevo** | `/api/audits/{id}/replay.json`: commit, versiones de motores, configuración no secreta y reglas inmunes vigentes |
| B19 | Procesamiento seguro | **nuevo** | Allowlist de propietarios `SECAUDIT_ALLOWED_REPO_OWNERS`; límites `SECAUDIT_MAX_SCAN_CHARS` y `SECAUDIT_MAX_SCAN_FILES`; git sin ext-diff ni textconv. Los parsers (ast, JSON, TOML, regex) corren en un proceso hijo aparte (`analysis/scan.py` vía `web/scanproc.py`) con `python3 -E -s`, entorno reducido a una allowlist (sin claves ni `DATABASE_URL`), límites de CPU, memoria y tamaño de fichero, y timeout (`SECAUDIT_SCAN_TIMEOUT`, `SECAUDIT_SCAN_MEMORY_MB`). Un fichero hostil tumba ese proceso, no el servidor |
| B20 | Reglas propuestas por IA | **existente** | `immune.py`: una regla solo se guarda si detecta el código antes del arreglo y no después |
| B21 | Fronteras de confianza | **nuevo** | `analysis/surface.py`, en el apartado `boundaries`. Cada entrada dice además si se ve validación de la entrada (`declared`/`none_seen`) |

### C. Funcionalidades diferenciales

| # | Funcionalidad | Estado | Dónde |
|---|---|---|---|
| C22 | ADN del proyecto | **nuevo** | `/api/projects/{id}/history`, en la sección «Cambios» |
| C23 | Ghost Dependencies y código muerto | **nuevo** | `deps.ghost_dependencies`: declaradas y no mencionadas en ningún otro sitio. `analysis/deadcode.py`: funciones Python de nivel superior y exports JS sin mención, ficheros nunca importados y blueprints de Flask nunca registrados. Es un sitio que mirar, no un hallazgo |
| C24 | Security Drift | **nuevo** | `drift.py`: 12 reglas sobre el diff; un control que solo se mueve no cuenta |
| C25 | Línea temporal de exposición de secretos | **nuevo** | `secrets_scan.timeline`: primer commit, commit de eliminación y si sigue en HEAD |
| C26 | Memoria adversarial con curación humana | **nuevo** | `immune.py` y las regresiones (zombies). Una regla validada queda como propuesta hasta que una persona la aprueba (`POST/DELETE .../immune-rules/{id}/approval`); solo las aprobadas buscan regresiones, se exportan y se usan en What If. Las reglas anteriores a la migración `0017` empiezan sin aprobar |
| C27 | Explorador de superficie de ataque e inventario de servicios | **nuevo** | `surface.py`: Flask, FastAPI, Django, Express, Next.js, herramientas MCP, CLIs y tareas. Servicios: contenedores de compose (imagen, puertos publicados, privileged, red del host), objetos Kubernetes, almacenes de datos, hosts externos y SDK de terceros |
| C28 | Contrafactuales | **nuevo** | `evidence_chain.counterfactuals`: condiciones verificadas, descartadas o desconocidas |
| C29 | What If? | **nuevo** | `web/whatif.py`. El parche se aplica a un clon temporal del commit auditado, nunca al original, y se mide sin ejecutar nada: si el código citado sigue ahí, qué hallazgos de regla desaparecen o aparecen, si las reglas inmunes aprobadas vuelven a saltar, si el parche debilita un control (deriva) y qué tests cubren los ficheros tocados, por nombre. Con el sandbox activado (`SECAUDIT_WHATIF_SANDBOX=docker`, `web/sandbox.py`), los tests del repositorio se ejecutan antes y después del parche en contenedores desechables sin red, de solo lectura, sin capacidades, como nobody y con límites; un test que el parche rompe cuenta en contra. Desactivado por defecto (ver §5) |
| C30 | Blue Team | **nuevo** | `reports.blue_team`: plantillas de detección y esqueleto Sigma, siempre marcadas «NO VALIDADO», en JSON, HTML y en la UI (botón en cada hallazgo) |
| C31 | Explain Like an Analyst | **nuevo** | Tres vistas en la UI y en el informe HTML (dirección, desarrollo, analista), sección «Vistas», y `assessment.why` |
| C32 | Replay | **nuevo** | `POST /api/audits/{id}/replay` relanza la auditoría sobre el mismo commit exacto, con las versiones actuales de los motores. `GET .../reproducibility` compara: hallazgos en ambas, solo en una, evaluación cambiada, acuerdo y si las reglas coinciden. Con un modelo, la diferencia mide también su variabilidad |
| C33 | Challenge Mode | **nuevo** (escáneres) | `analysis/benchmark.py` y un corpus propio en `benchmark/`: 38 etiquetas en 8 repositorios, con controles limpios y engaños. Además, OWASP NodeGoat etiquetado desde su propio tutorial antes de pasar los escáneres (`benchmark/external/`). Ejecutado: ver §7. Mide los escáneres deterministas; la auditoría del modelo hay que puntuarla con el backend de cada uno |
| C34 | Digital Twin | **nuevo** | `analysis/twin.py` y la sección «Gemelo»: áreas, entradas, activos, servicios, dependencias, hallazgos y atacantes, con sus relaciones y lo que se desconoce de cada nodo. Es un mapa, no una copia ejecutable. Simulación (`POST .../twin/simulate`): arreglar o confirmar hallazgos (y retirar capacidades del agente o divergencias) y recalcular los caminos de ataque: cuáles se cierran, cambian o se abren |
| C35 | Evidence Chain | **nuevo** | `analysis/evidence_chain.py`, con hash SHA-256 de la cadena y del fragmento citado |

### D. Auditor de seguridad MCP

**Nuevo y obligatorio.** `analysis/mcp_audit.py` cubre las 10 categorías del
OWASP MCP Top 10 2025 (Beta, Phase 3), consultado el 2026-11-02 en
https://owasp.org/www-project-mcp-top-10/. Detalle en §4. Además:

- los hallazgos MCP entran en los caminos de ataque y hay un señuelo MCP;
- la taxonomía se puede comprobar contra la página oficial bajo demanda
  (`POST /api/mcp/taxonomy-check` o `python3 -m analysis.mcp_audit
  --check-taxonomy`). Solo se descarga la página; no se envía nada del
  repositorio. Comprobado el 2026-11-02: coincide (10 categorías, edición
  2025).

## 3. Arquitectura

```
clone (gitclone, allowlist de propietarios)
   │
   ├─► proceso aislado (runner) ── modelo ─► hallazgos del modelo
   │                                            │
   │                       evidence.verify_findings (checkout del servidor)
   │                                            │
   ├─► proceso hijo aislado (scanproc → analysis.scan, límites + timeout)
   │        ├─ secrets_scan  (+ timeline)  ─┐
   │        ├─ deps                        │
   │        ├─ mcp_audit                   ├─► hallazgos source="rule"
   │        ├─ taint                      ─┘   (verificados igual)
   │        └─ surface · doc_claims · deadcode ─► module_runs
   │     (OSV y registros: en el servidor, opt-in)
   │
   ├─► store_result ─► findings (source, rule_id, detail), components
   ├─► falsify · parallax · immune · leverage · attacker  (existentes)
   └─► drift (base: anterior, base_ref o la base del PR) ─► module_runs
                │
   API ─► assessment · evidence_chain · trust · reports (SARIF/JSON/HTML/PDF/CDX)
          twin · blue team · what if (clon temporal) · replay
```

Decisiones de diseño:

- **Los hallazgos de regla viven en la misma tabla** que los del modelo
  (`findings.source`, `rule_id`, `detail`). Así heredan la UI, los filtros, la
  refutación, los caminos de ataque, SARIF y la puntuación de confianza.
  `finding_from_dict` anula esos campos, de modo que el proceso que habla con
  el modelo nunca puede hacerse pasar por una regla.
- **La evaluación se calcula, no se guarda**:
  - `refuted` → DESCARTADO.
  - `unverified` o `needs_dynamic_test` → NO VERIFICABLE.
  - Si no, la que fije la regla.
  - Si no, `corroborated` → CONFIRMADO, y cualquier otro estado verificado →
    POTENCIAL.
- **Nada sale del servidor sin consentimiento**: OSV está desactivado por
  defecto y, si se activa, solo envía nombre, ecosistema y versión exacta.
- **Ningún CVSS inventado**: la severidad de una vulnerabilidad conocida se
  toma del aviso; si no la trae, no hay.
- Tabla nueva `components` y columnas nuevas en `findings`: migración
  `0016_rules_and_components` (aditiva, reversible).
- Aprobación de reglas, auditorías fijadas a un commit y comparadas con una
  base, mantenimiento de dependencias y la tabla `what_ifs`: migración
  `0017_approval_replay_whatif` (aditiva, reversible).

### Endpoints nuevos

Todos exigen ser el dueño de la auditoría; la de otro usuario responde 404.

| Método y ruta | Devuelve |
|---|---|
| `GET /api/audits/{id}/trust` | Las tres dimensiones de confianza y los límites |
| `GET /api/audits/{id}/findings/{fid}/evidence-chain` | La cadena de evidencia de un hallazgo |
| `GET /api/audits/{id}/report.sarif` | SARIF 2.1.0; los descartados van como supresiones |
| `GET /api/audits/{id}/report.json` | Informe completo con cadenas de evidencia |
| `GET /api/audits/{id}/report.html` | Informe autónomo, sin scripts y con CSP `default-src 'none'` |
| `GET /api/audits/{id}/components` | Inventario de dependencias |
| `GET /api/audits/{id}/sbom.cdx.json` | SBOM CycloneDX 1.5 |
| `GET /api/audits/{id}/diff` | Cambios de hallazgos frente a la auditoría anterior |
| `GET /api/audits/{id}/replay.json` | Manifiesto de reproducibilidad |
| `GET /api/projects/{id}/history` | ADN del proyecto |
| `GET /api/mcp/catalog?language=es` | Catálogo MCP01-MCP10, con la última comprobación de la taxonomía |
| `POST /api/mcp/taxonomy-check` | Compara la taxonomía con la página oficial de OWASP (caché de 24 h) |
| `GET /api/audits/{id}/report.pdf` | Informe PDF |
| `GET /api/audits/{id}/findings/{fid}/blue-team` | Plantillas de detección, NO VALIDADAS |
| `GET /api/audits/{id}/twin` | Gemelo digital |
| `POST /api/audits/{id}/twin/simulate` | Caminos de ataque tras arreglar o confirmar hallazgos (no escribe nada) |
| `POST` y `GET /api/audits/{id}/what-if` | Probar un parche en un clon temporal; historial |
| `POST /api/audits/{id}/replay` | Repetir la auditoría sobre el mismo commit |
| `GET /api/audits/{id}/reproducibility` | Comparación de un replay con su original |
| `POST` y `DELETE /api/projects/{id}/immune-rules/{rid}/approval` | Aprobar o retirar una regla aprendida |

`POST /api/audits` acepta además `branch`, `base_ref` (rama o commit con el
que comparar) y `commit` (40 caracteres hexadecimales). El webhook atiende
`push` y `pull_request`.

UI: secciones nuevas **Vistas**, **MCP**, **Cadena de suministro**,
**Superficie de ataque**, **Cambios** y **Gemelo**. En el resumen se añaden la confianza, las
exportaciones y el recuento por evaluación. Cada hallazgo muestra su
evaluación, su insignia OWASP MCP y un botón para ver la cadena de evidencia.
Hay un filtro nuevo por evaluación.

## 4. Auditor MCP: catálogo

El texto completo de cada categoría está en `mcp_audit.CATALOG` (en y es) y
en la API. Cada categoría define:

- los artefactos inspeccionados;
- los patrones estáticos;
- las condiciones de confirmación;
- los falsos positivos conocidos;
- la mitigación;
- los límites.

Resumen de reglas:

| Categoría | Reglas |
|---|---|
| MCP01 Token Mismanagement & Secret Exposure | `literal_secret_in_config`, `token_in_url`, `environment_exposed` |
| MCP02 Privilege Escalation via Scope Creep | `enable_all_project_servers`, `wildcard_tool_permission`, `auto_approved_tools`, `broad_filesystem_root`, `dangerous_flag` |
| MCP03 Tool Poisoning | `invisible_characters` (confirmado), `instructions_in_description`, `oversized_description`, `dynamic_description`, `tool_name_collision` |
| MCP04 Software Supply Chain Attacks & Dependency Tampering | `unpinned_package`, `unpinned_image`, `pipe_to_shell`, `plain_http_remote` |
| MCP05 Command Injection & Execution | `exec_in_tool` (confirmado y crítico si un parámetro llega a la ejecución) |
| MCP06 Prompt Injection via Contextual Payloads | `external_content_unmarked` (siempre NO VERIFICABLE: requiere prueba dinámica) |
| MCP07 Insufficient Authentication & Authorization | `remote_without_credentials`, `network_server_without_auth` |
| MCP08 Lack of Audit and Telemetry | `no_logging` |
| MCP09 Shadow MCP Servers | `tunnel_or_raw_ip`, `nested_config`, `undeclared_server` |
| MCP10 Context Injection & Over-Sharing | `unconfined_path`, `select_star`, `recursive_listing`, `file_resource_template` |

Cada resultado incluye:

- la categoría y su id OWASP;
- el commit SHA, el fichero y la línea;
- la evidencia redactada (secretos y tokens en URL enmascarados);
- los prerrequisitos, el impacto, la confianza y la evaluación.

Los resultados entran en el informe SARIF, JSON y PDF, en la UI, en la cadena
de evidencia y en la puntuación de confianza (como cualquier hallazgo).
También entran en los caminos de ataque. `attacker._MCP_STEPS` da a cada
regla un paso; por ejemplo:

- MCP07 servidor de red sin autenticación: petición → agente;
- MCP05 ejecución en herramienta: agente → ejecución de código;
- MCP01 entorno expuesto: agente → secretos;
- MCP04 paquete sin fijar: dependencia comprometida → máquina del desarrollador.

Un paso solo es sólido si el hallazgo está CONFIRMADO. Un hallazgo descartado
o sin verificar no da paso.

`canary.py` tiene un señuelo MCP (`mcp_tool_exec`): una herramientas
decorada que pasa su parámetro a un shell. Mide si el modelo la detecta.

Uso sin servidor (solo lectura, no arranca nada):

```bash
python3 -m analysis.mcp_audit /ruta/al/repo
```

Límites: el análisis es estático y nunca arranca, instala ni conecta un
servidor MCP. Por eso no detecta:

- descripciones que cambian en ejecución (*rug pull*), más allá de marcarlas
  como dinámicas;
- autenticación aplicada por un proxy;
- servidores configurados fuera del repositorio.

Las herramientas JavaScript se leen por patrón, con menos confianza que las
de Python, que se leen con ast.

## 5. Limitaciones

- **Una auditoría sin alertas no es una garantía.** La puntuación de
  confianza lo dice siempre en sus límites. Además, la marca
  `unreliable_clean` avisa cuando un resultado limpio se apoya en poca
  cobertura o en señuelos no detectados.
- No se ejecuta código del repositorio auditado: la explotación se argumenta
  desde el código, nunca se demuestra. Por eso existe NO VERIFICABLE.
- **El sandbox de What If es la única excepción** a no ejecutar código
  auditado, y está desactivado por defecto. Cuando se activa:
  - los tests corren en un contenedor Docker desechable, sin red, de solo
    lectura, sin capacidades, como nobody y con límites; se comprobó desde
    dentro del propio contenedor;
  - instalar dependencias exige red y se hace solo con
    `SECAUDIT_SANDBOX_INSTALL=1`, en otro contenedor. npm va con
    `--ignore-scripts`, pero pip puede ejecutar código de construcción de un
    paquete (dentro del contenedor);
  - un contenedor no es una máquina virtual: comparte el kernel del host;
  - **en producción sigue desactivado**: la app corre en un contenedor sin
    Docker, y montarle el socket de Docker le daría control del host.
  Sin sandbox, What If mide sin ejecutar nada y lista los tests por nombre.
  «Prometedor» es indicio de arreglo, no prueba.
- La detección de secretos funciona por formato y entropía. Puede fallar con
  formatos propios y dar falsos positivos en datos de prueba. Los ficheros de
  fixtures rebajan la severidad, pero siguen como POTENCIAL; el benchmark lo
  cuenta como falso positivo. La línea temporal se limita al historial
  descargado (`SECAUDIT_HISTORY_DEPTH`).
- Dependencias:
  - Maven y Gradle: una versión que viene de un pom padre, un BOM, una
    propiedad definida en otro fichero, una variable no literal o un rango
    dinámico (`1.+`) se deja sin versión, no se adivina. Gradle se lee como
    texto: lo que un plugin o un script añade en ejecución no se ve;
  - las transitivas solo aparecen si hay lockfile, y la UI avisa cuando no
    lo hay;
  - el mantenimiento solo se consulta en PyPI, npm y crates.io.
- Taint:
  - sigue funciones auxiliares del mismo fichero (hasta tres llamadas de
    profundidad), con confianza baja en esos flujos; no sigue atributos,
    contenedores, funciones que comparten nombre ni otros ficheros. Una
    función desconocida (de otro fichero o de una librería) se trata de forma
    conservadora: si recibe la entrada, su resultado se da por contaminado;
  - reconoce los saneadores por nombre;
  - JS/TS con tree-sitter sigue el mismo alcance (un fichero); sin
    tree-sitter instalado se lee por patrón, con confianza baja, y la
    salida lo dice (`js_parser`);
  - no cubre otros lenguajes, y lo dice en `not_analysed`.
- Documentación frente a código: se busca evidencia por patrón. «Sin
  respaldo» puede significar que el control está en un proxy, en la
  infraestructura o en una librería no reconocida.
- Código muerto: el uso dinámico (`getattr`, registro por cadena,
  frameworks que descubren por nombre) no se ve. Por eso es un sitio que
  mirar.
- La superficie de ataque solo inventaría Python (con ast) y JS/TS (por
  patrón). Para otros lenguajes se indica en `not_inventoried`. Un
  «auth: none_seen» o «validación: none_seen» es un sitio que mirar, no un
  hallazgo.
- La deriva aplica patrones sobre un diff y señala sitios, no veredictos.
- Informe en el PR: desactivado por defecto. En modo `full` y en un
  repositorio público, el comentario dice dónde están los hallazgos nuevos.
  Un estado «success» significa «sin hallazgos altos nuevos ni controles
  debilitados», no «seguro».
- Las plantillas Blue Team no están validadas contra telemetría real.
- El gemelo digital es un mapa de lo medido: no se puede ejecutar. Su
  simulación recalcula caminos sobre el grafo que midió la auditoría; un
  camino que el grafo no contiene no se puede cerrar ni abrir ahí. La
  ausencia de un nodo no significa que la cosa no exista.
- El corpus propio del benchmark lo escribió quien escribió los escáneres:
  es optimista. NodeGoat es independiente, pero es un único repositorio de
  14 etiquetas. Además, su tutorial no recoge todo lo que tiene (los dos
  hallazgos «inesperados» eran reales). Ver `benchmark/README.md`.

## 6. Pendiente

Lo que sigue no está implementado:

- **Sandbox de What If en producción**: necesitaría un servicio de
  ejecución aparte en el VPS (o gVisor/una VM), no el socket de Docker en la
  app.
- **Simulación del gemelo que añada entradas o controles nuevos** (hoy se
  puede arreglar o confirmar lo que existe, no inventar lo que no está).
- **Taint entre ficheros** (NodeGoat lo muestra: la inyección `$where` va
  de `allocations.js` a `allocations-dao.js`).
- **Validación de las plantillas Blue Team** contra telemetría.
- **Puntuar la auditoría del modelo** sobre NodeGoat con un backend real, y
  etiquetar más repositorios externos (DVWA, Juice Shop…).
- **Poms padre y BOM** de Maven (requerirían descargar otros poms).
- **Fallos medidos por el benchmark:** `mcp10.unconfined_path` no reconoce
  `Path(param).read_text()`; `mcp09.undeclared_server` da falsos positivos en
  servidores pensados para que los configure quien los instala; un token en
  `tests/fixtures/` queda POTENCIAL. No se han corregido a propósito, para no
  ajustar los escáneres al corpus que los mide.

## 7. Pruebas ejecutadas

Todos los resultados son reales, del 2026-11-02:

| Comando | Resultado |
|---|---|
| `SECAUDIT_TEST_DOCKER=1 python3 -m pytest tests/ -q -p no:cacheprovider` | 947 passed |
| `python3 -m analysis.benchmark --external benchmark/external/nodegoat.json` | en alcance de los escáneres 5/5; entre ficheros 0/1; solo-modelo 0/8; total 5/14; 2 hallazgos fuera de etiqueta, ambos reales tras revisarlos |
| Prueba real del sandbox con Docker (`python:3.12-slim`) | un parche que rompe un test sale «introduce problemas»; desde dentro: usuario 65534, sin red, raíz de solo lectura, CapEff 0, sin secretos del host |
| `node --check web/static/app.js` | ok |
| `python3 -m analysis.benchmark --corpus benchmark` | 38 etiquetas, 37 TP, 3 FP, 1 FN; precisión 0.925, recall 0.974 |
| `python3 -m analysis.mcp_audit --check-taxonomy` | coincide: 10 categorías, edición 2025 |

Qué cubren los tests de la segunda parte (`tests/test_practica3b.py`):

- Taint:
  - flujos Python y JS;
  - su ausencia con consultas parametrizadas, `int()` o funciones sin fuente;
  - el flujo paso a paso.
- Documentación: afirmaciones respaldadas, sin respaldo y contradichas, en
  inglés y en español.
- Código muerto: funciones, ficheros, exports y blueprints; los puntos de
  entrada de framework no cuentan.
- Dependencias:
  - Cargo, RubyGems, Composer y Maven;
  - el mantenimiento con un registro simulado (las transitivas no se
    consultan);
  - un error del registro se cuenta y no se adivina;
  - las señales citan la línea tal como está escrita.
- Superficie: validación y servicios.
- MCP:
  - un camino anónimo → ejecución de código a través de MCP07 y MCP05;
  - un hallazgo descartado no da paso;
  - el señuelo MCP se planta y se localiza;
  - la taxonomía coincide, una categoría renombrada se detecta y la falta de
    red se dice.
- PDF: estructura, tabla xref, escapado y ausencia de JavaScript.
- Proceso aislado:
  - todos los escáneres responden;
  - el hijo no recibe la clave maestra ni `DATABASE_URL`;
  - un timeout da error.
- What If:
  - rechaza parches fuera del repositorio, enlaces simbólicos y binarios;
  - un arreglo real sale «prometedor» y no toca el repositorio original;
  - un parche que abre CORS sale «introduce problemas».
- Replay: mismo commit y acuerdo 1.0. Una base elegida y un commit exacto.
- Pull requests: el webhook audita la cabeza contra la base, ignora un fork
  fuera de la allowlist y no hace nada al cerrar.
- Gemelo, Blue Team y PDF a través de la aplicación, sin fugas del token.
- Aprobación de reglas: una regla sin aprobar no detecta nada, y aprobar una
  no validada da 409.
- El benchmark se ejecuta y el corpus no guarda ninguna cadena con forma de
  credencial.

Tercera parte (después de la versión 0.4.0, en la misma fecha):

- Maven con propiedades, Gradle, catálogos de versiones y `gradle.lockfile`.
- Taint entre funciones del mismo fichero, con un caso nuevo en el corpus
  (`flask-helpers`). Lo escribió quien escribió el análisis, después de
  escribirlo, y el benchmark lo dice. Al añadirlo apareció un falso positivo
  real (el resultado de una función auxiliar que sanea con `int()` se daba
  por contaminado) y se corrigió.
- Simulación sobre el gemelo, comprobada también en el navegador con la demo
  local: arreglar MCP05 cerró 4 de 8 caminos.

Cuarta parte (con autorización explícita de la usuaria para lo pendiente):

- Taint JS/TS con tree-sitter. Sobre NodeGoat, el lector por patrones
  encontraba 1 de 5 casos en alcance; tree-sitter encuentra 5 de 5.
- Informe en el PR (comentario y estado), opcional, migración `0018`.
- Sandbox de What If con Docker, opcional, probado con Docker real.
- Benchmark externo con NodeGoat.

Durante esta parte los tests encontraron tres fallos en código nuevo, ya
corregidos:

- What If daba siempre «el código citado ya no está», porque partía de un
  estado no verificado y la comprobación de evidencia solo degrada.
- El gemelo fallaba con un parámetro duplicado.
- Las señales de dependencias de Cargo y de lockfiles citaban texto
  normalizado que no estaba en el fichero, y quedaban NO VERIFICABLES.

## 8. Despliegue

Desplegado el 2026-11-02 en secaudit.ksabitova.dev, con copia previa de la
base de datos. Las migraciones `0016`–`0018` se aplicaron al arrancar, el
análisis con tree-sitter está activo y el sandbox y el informe en el PR están
apagados. Producción no tenía reglas inmunes que aprobar. Para otro
despliegue hay que:

1. Aplicar las migraciones `0016`, `0017` y `0018`; la próxima será la `0019`.
2. **Tras desplegar, aprobar las reglas inmunes existentes** que se quieran
   mantener: la `0017` las deja todas sin aprobar y, hasta entonces, no
   buscan regresiones.
3. Opcionalmente, fijar `SECAUDIT_ALLOWED_REPO_OWNERS`, `SECAUDIT_OSV_CHECK`,
   `SECAUDIT_ABANDONED_CHECK`, `SECAUDIT_SCAN_TIMEOUT` y
   `SECAUDIT_SCAN_MEMORY_MB` (ver `.env.example`).
4. Para el diferencial de PR, añadir el evento `pull_request` al webhook de
   GitHub.
5. Para el informe en el PR, crear un token de GitHub con «Pull requests:
   write» y «Commit statuses: write» solo para los repositorios auditados,
   y fijar `SECAUDIT_GITHUB_WRITE_TOKEN` y `SECAUDIT_PR_COMMENTS=summary`.
6. **No activar `SECAUDIT_WHATIF_SANDBOX` en el VPS**: la app corre en un
   contenedor y necesitaría el socket de Docker, que da control del host.
