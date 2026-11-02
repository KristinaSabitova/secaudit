# secaudit — práctica 3: estado, arquitectura y plan

Fecha: 2026-11-02 · versión de la herramienta: 0.3.0 · migración: 0016.

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
auditado.

### B. Ampliaciones

| # | Funcionalidad | Estado | Dónde |
|---|---|---|---|
| B10 | Dependencias, SBOM y OSV | **nuevo** | `analysis/deps.py`; CycloneDX 1.5 en `/sbom.cdx.json`; OSV solo con `SECAUDIT_OSV_CHECK=1` |
| B11 | Taint | **parcial** | Python: refutación por flujo (`falsify.py`, existente) y taint de parámetros en herramientas MCP (`mcp_audit.py`). Sin taint completo para otros lenguajes |
| B12 | Prompt injection | **existente + nuevo** | Instrucciones ocultas en ficheros de agente (`parallax.py`); envenenamiento de herramientas MCP (MCP03, MCP06) |
| B13 | Impacto | **existente** | `leverage.py`, `attacker.py` |
| B14 | Diferencial | **nuevo** | `analysis/drift.py`: hallazgos nuevos, corregidos, persistentes y reintroducidos; `/api/audits/{id}/diff` |
| B15 | Informes PDF / JSON / SARIF | **nuevo** (PDF parcial) | `analysis/reports.py`. El PDF es el informe HTML impreso desde el navegador, para no añadir una dependencia pesada |
| B16 | Trust Score | **nuevo** | `analysis/trust.py`: tres dimensiones separadas (cobertura, evidencia, resistencia adversarial), sin nota global a propósito |
| B17 | Detección de secretos | **nuevo** | `analysis/secrets_scan.py`, con valores siempre enmascarados `[REDACTED:<hash>]` |
| B18 | Reproducibilidad | **nuevo** | `/api/audits/{id}/replay.json`: commit, versiones de motores, configuración no secreta y reglas inmunes vigentes |
| B19 | Procesamiento seguro | **existente + nuevo** | Allowlist de propietarios `SECAUDIT_ALLOWED_REPO_OWNERS`; límites `SECAUDIT_MAX_SCAN_CHARS` y `SECAUDIT_MAX_SCAN_FILES`; git sin ext-diff ni textconv; parsers con ast/regex y sin ejecución |
| B20 | Reglas propuestas por IA | **existente** | `immune.py`: una regla solo se guarda si detecta el código antes del arreglo y no después |
| B21 | Fronteras de confianza | **nuevo** | `analysis/surface.py`, en el apartado `boundaries` |

### C. Funcionalidades diferenciales

| # | Funcionalidad | Estado | Dónde |
|---|---|---|---|
| C22 | ADN del proyecto | **nuevo** | `/api/projects/{id}/history`, en la sección «Cambios» |
| C23 | Ghost Dependencies | **nuevo** | `deps.ghost_dependencies`: declaradas y no mencionadas en ningún otro sitio |
| C24 | Security Drift | **nuevo** | `drift.py`: 12 reglas sobre el diff; un control que solo se mueve no cuenta |
| C25 | Línea temporal de exposición de secretos | **nuevo** | `secrets_scan.timeline`: primer commit, commit de eliminación y si sigue en HEAD |
| C26 | Memoria adversarial | **existente** | `immune.py` y las regresiones (zombies) |
| C27 | Explorador de superficie de ataque | **nuevo** | `surface.py`: Flask, FastAPI, Django, Express, Next.js, herramientas MCP, CLIs y tareas |
| C28 | Contrafactuales | **nuevo** | `evidence_chain.counterfactuals`: condiciones verificadas, descartadas o desconocidas |
| C29 | What If? | **pendiente** | Ver §6 |
| C30 | Blue Team | **nuevo** (parcial) | `reports.blue_team`: plantillas de detección y esqueleto Sigma, siempre marcadas «NO VALIDADO». Solo en informes JSON y HTML, no en la UI |
| C31 | Explain Like an Analyst | **nuevo** | Tres vistas del informe HTML (dirección, desarrollo, analista) y `assessment.why` |
| C32 | Replay | **parcial** | Se exporta el manifiesto; no hay re-ejecución automática |
| C33 | Challenge Mode | **parcial** | `analysis/benchmark.py`: TP/FP/FN, precisión, recall, F1 y aviso de muestra pequeña. No hay corpus etiquetado propio salvo el laboratorio |
| C34 | Digital Twin | **pendiente** | Ver §6 |
| C35 | Evidence Chain | **nuevo** | `analysis/evidence_chain.py`, con hash SHA-256 de la cadena y del fragmento citado |

### D. Auditor de seguridad MCP

**Nuevo y obligatorio.** `analysis/mcp_audit.py` cubre las 10 categorías del
OWASP MCP Top 10 2025 (Beta, Phase 3), consultado el 2026-11-02 en
https://owasp.org/www-project-mcp-top-10/. Detalle en §4.

## 3. Arquitectura

```
clone (gitclone, allowlist de propietarios)
   │
   ├─► proceso aislado (runner) ── modelo ─► hallazgos del modelo
   │                                            │
   │                       evidence.verify_findings (checkout del servidor)
   │                                            │
   ├─► parallax.repository_texts (acotado) ─► run_rule_scanners
   │        ├─ secrets_scan  (+ timeline)  ─┐
   │        ├─ deps          (+ OSV opt-in) ├─► hallazgos source="rule"
   │        └─ mcp_audit                   ─┘   (verificados igual)
   │
   ├─► store_result ─► findings (source, rule_id, detail), components
   ├─► falsify · parallax · immune · leverage · attacker  (existentes)
   └─► surface · drift ─► module_runs
                │
   API ─► assessment · evidence_chain · trust · reports (SARIF/JSON/HTML/CDX)
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
| `GET /api/mcp/catalog?language=es` | Catálogo MCP01-MCP10 |

UI: secciones nuevas **MCP**, **Cadena de suministro**, **Superficie de
ataque** y **Cambios**. En el resumen se añaden la confianza, las
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

Los resultados entran en el informe SARIF y JSON, en la UI, en la cadena de
evidencia, en la puntuación de confianza y en los caminos de ataque.

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
- La detección de secretos funciona por formato y entropía. Puede fallar con
  formatos propios y dar falsos positivos en datos de prueba; los ficheros de
  fixtures rebajan la severidad y quedan como POTENCIAL. La línea temporal se
  limita al historial descargado (`SECAUDIT_HISTORY_DEPTH`).
- Las dependencias se leen de requirements, pyproject, poetry.lock, uv.lock,
  package.json, package-lock y go.mod:
  - otros ecosistemas, como Maven, Gradle, Cargo o Gemfile, no se inventarían;
  - las transitivas solo aparecen si hay lockfile;
  - no se detectan paquetes abandonados.
- La superficie de ataque solo inventaría Python (con ast) y JS/TS (por
  patrón). Para otros lenguajes se indica en `not_inventoried`. Un
  «auth: none_seen» es un sitio que mirar, no un hallazgo.
- La deriva aplica patrones sobre un diff y señala sitios, no veredictos.
- Las plantillas Blue Team no están validadas contra telemetría real.
- No hay benchmark publicado: Challenge Mode calcula las métricas, pero no
  hay un corpus etiquetado de tamaño suficiente (≥ 30 etiquetas) aparte del
  laboratorio.

## 6. Pendiente (con contrato)

- **C29 What If?** Requiere ejecutar los tests del repositorio con un parche
  aplicado, lo que choca con la regla de no ejecutar código auditado.
  - Contrato propuesto: `POST /api/audits/{id}/findings/{fid}/what-if` con un
    parche.
  - Se ejecutaría solo en un sandbox efímero sin red (contenedor sin
    capacidades, con límites de CPU, memoria y tiempo, en un sistema de
    ficheros de solo lectura salvo `/tmp`).
  - Se activaría solo con un opt-in explícito del administrador.
  - Devolvería si los tests pasan y si el hallazgo desaparece.
- **C34 Digital Twin.** Un modelo del sistema (entradas, activos y fronteras
  de `surface.py` más los caminos de `attacker.py`) sobre el que simular
  cambios sin tocar el repositorio.
  - Contrato propuesto: `GET /api/audits/{id}/twin` con nodos y aristas, y
    `POST .../twin/simulate` con `{remove_control | add_entry}`, que
    devolvería los caminos de ataque afectados.
  - Base disponible: `surface.boundaries` y `attacker`.
- **C32 Replay ejecutable:** relanzar una auditoría desde `replay.json` sobre
  el mismo commit y comparar huellas.
- **B11 taint en otros lenguajes:** JS/TS con un parser real. Sería una
  dependencia nueva y requiere autorización.
- **Paquetes abandonados:** fecha del último release en el registro. Sale
  del servidor, así que tendría que ser opt-in como OSV.
- **Blue Team en la UI** y validación de las plantillas.
- **Corpus de Challenge Mode:** etiquetar al menos 30 casos (repos vulnerables
  conocidos, como NodeGoat, más controles limpios) y publicar los resultados
  con su tamaño de muestra.

## 7. Pruebas ejecutadas

Todos los resultados son reales, del 2026-11-02:

| Comando | Resultado |
|---|---|
| `python3 -m pytest tests/ -q -p no:cacheprovider` | 868 passed |
| `python3 -m pytest tests/test_mcp_audit.py -q` | 36 passed |
| `python3 -m pytest tests/test_practica3.py -q` | 47 passed |
| `python3 -m pytest tests/test_mcp_audit.py tests/test_practica3.py tests/test_schema.py tests/test_frontend.py -q` | 122 passed |
| `node --check web/static/app.js` | ok |

Qué cubren los tests nuevos:

- Casos positivos y negativos para cada categoría MCP01-MCP10.
- Un repositorio limpio que no da ningún hallazgo.
- Que ningún secreto aparece en ninguna salida: API, SARIF, JSON, HTML,
  SBOM, cadena de evidencia e inventario MCP.
- La línea temporal de secretos sobre un repositorio git real.
- OSV con un cliente HTTP simulado (nunca se llama a la red en los tests).
- La deriva y la diferencia de hallazgos.
- Los formatos de exportación.
- Las métricas del benchmark.
- La allowlist de propietarios.
- Los límites de lectura.
- Una auditoría completa a través de la aplicación web.

Verificación manual: se creó en local una base SQLite con dos auditorías de
un repositorio de laboratorio, usando un backend simulado y nunca la base de
producción. Se revisaron en el navegador las secciones Resumen, MCP, Cadena
de suministro, Superficie y Cambios, sin errores de consola. Los resultados
fueron:

- La deriva detectó `CORS_ALLOW_ALL_ORIGINS = True`.
- La clave AWS retirada aparece como corregida y, en la línea temporal, como
  «eliminado en 48755b7, sigue ahí: no».
- El token en la URL MCP aparece redactado.

## 8. Despliegue

No se ha desplegado nada. Para desplegar hay que:

1. Aplicar la migración `0016`; la próxima migración será la `0017`.
2. Opcionalmente, fijar `SECAUDIT_ALLOWED_REPO_OWNERS` y `SECAUDIT_OSV_CHECK`
   (ver `.env.example`).
