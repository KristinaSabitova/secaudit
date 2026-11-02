# Guía de uso de secaudit

Esta guía explica cómo usar la aplicación web paso a paso: lanzar una
auditoría y saber qué mirar en cada sección. Para instalar y desplegar, ver
el [README](../README.es.md). Para saber el estado de cada funcionalidad y
sus límites, ver [PRACTICA3.md](PRACTICA3.md).

## Antes de empezar

- secaudit **nunca ejecuta** el código del repositorio auditado. No ejecuta
  sus scripts de instalación, hooks, workflows ni tests. Todo lo que lee lo
  trata como datos no confiables.
- **Una auditoría sin hallazgos no es una garantía.** Mira siempre la
  confianza del resumen y sus límites.
- Por defecto, nada del repositorio sale del servidor salvo lo que enviaría
  al modelo el backend que hayas configurado. Puedes usar ollama en local y
  así no sale nada. OSV y los registros de paquetes son opcionales (ver
  §Ajustes).

## 1. Lanzar una auditoría

1. Inicia sesión y escribe la URL del repositorio en el formulario
   principal. Si el administrador fijó `SECAUDIT_ALLOWED_REPO_OWNERS`, solo
   se aceptan repositorios de esos propietarios.
2. Al desplegar **opciones** puedes indicar:
   - **Rama**: la que se clona (por defecto, la principal).
   - **Base**: una rama o commit con el que comparar. Sin base, se compara
     con la auditoría anterior del mismo proyecto.
   - **Commit**: un commit exacto, con sus 40 caracteres hexadecimales.
3. La auditoría pasa por *pendiente* → *en curso* → *hecha*. Con el backend
   `claude-code`, espera a que el runner la recoja.

### Desde GitHub (push y pull requests)

Configura un webhook hacia `/api/webhook/github` con el secreto
`GITHUB_WEBHOOK_SECRET` y los eventos `push` y `pull_request`.

- Un pull request se audita en su commit de cabeza y se compara con su
  base.
- Un fork cuyo propietario no está en la allowlist se ignora.
- secaudit no escribe comentarios en el PR: los resultados se consultan en
  la aplicación.

## 2. Leer el resultado

### Resumen

- **Confianza**: tres medidas por separado, a propósito sin una nota
  global:
  - *cobertura*: cuánto del código se leyó de verdad;
  - *calidad de la evidencia*: cuántos hallazgos citan código que el
    servidor ha encontrado;
  - *resistencia adversarial*: si el auditor detectó los señuelos.

  Debajo están los **límites**: léelos.
- **Recuento por evaluación**:
  - **CONFIRMADO**: la evidencia y la corroboración lo sostienen;
  - **POTENCIAL**: el código citado existe, pero falta demostrar que es
    explotable;
  - **DESCARTADO**: se refutó;
  - **NO VERIFICABLE**: requiere una prueba dinámica que secaudit no hace.
- **Exportar**: SARIF (para GitHub code scanning), JSON, HTML, PDF y SBOM
  CycloneDX.
- **repetir esta auditoría**: relanza la auditoría sobre el mismo commit. Al terminar, el
  replay muestra cuánto coincide con el original: si las reglas dan lo mismo
  y cuánto varió el modelo.

### Hallazgos

Cada hallazgo muestra:

- el fichero y la línea;
- la evidencia;
- su evaluación;
- la insignia OWASP MCP, si aplica;
- el flujo de taint paso a paso, si viene del análisis de taint.

Y tiene tres botones:

- **ver la cadena de evidencia**: de dónde sale cada afirmación, con hashes.
- **propuesta de detección (Blue Team)**: plantillas de detección (también Sigma). Siempre van
  marcadas **NO VALIDADO**; adáptalas y pruébalas en tu telemetría antes de
  usarlas.
- **¿Y si…? Prueba un arreglo en una copia** (What If): pega un parche (`git diff`) que creas que lo arregla.
  secaudit lo aplica en un clon temporal, nunca en tu repositorio, y te dice:
  - si el código citado sigue ahí;
  - qué hallazgos de regla desaparecen o aparecen;
  - si el parche debilita algún control (por ejemplo, abre CORS);
  - si alguna regla aprendida aprobada vuelve a saltar;
  - qué tests cubren los ficheros tocados. **No los ejecuta**: ejecútalos tú
    en un entorno aislado.

  El veredicto puede ser *prometedor*, *introduce problemas* o *no
  demostrado*. *Prometedor* es un indicio, no una prueba.

### Vistas

La misma auditoría contada para tres públicos:

- **Dirección**: riesgo y prioridades.
- **Desarrollo**: qué cambiar y dónde.
- **Analista**: evidencia, evaluación y por qué.

La aplicación recuerda la vista elegida.

### Parallax

Compara lo que el repositorio dice de sí mismo con lo que hace:

- vistas que no coinciden;
- instrucciones ocultas para agentes;
- **afirmaciones de la documentación**. Cada una aparece como *respaldada*,
  *sin respaldo* o *contradicha* por el código. *Sin respaldo* puede querer
  decir que el control está en la infraestructura: compruébalo.

### Falsabilidad, memoria, palanca y atacante

- **Falsabilidad**: los intentos de refutar cada hallazgo.
- **Memoria**: las reglas aprendidas de arreglos anteriores. Una regla
  validada (detecta el código antes del arreglo y no después) queda
  **propuesta** hasta que la apruebas. Solo las aprobadas buscan
  regresiones, se exportan y se usan en What If. Puedes retirar la
  aprobación cuando quieras.
- **Palanca**: los ficheros en los que un cambio afecta a más cosas.
- **Atacante**: los caminos desde un perfil de atacante (anónimo, usuario,
  colaborador, dependencia comprometida) hasta lo valioso.
  - Un camino es **hipotético** si alguno de sus pasos se apoya en un
    hallazgo no confirmado.
  - Los pasos MCP llevan su categoría OWASP.

### MCP

- El inventario de servidores, clientes, configuraciones y herramientas MCP.
- Los hallazgos MCP01-MCP10.
- **comprobar ahora la taxonomía contra la página oficial**: compara las categorías con la página oficial de
  OWASP. Solo descarga esa página y no envía nada.

### Cadena de suministro

- Las dependencias por ecosistema, con sus vulnerabilidades si OSV está
  activo.
- El mantenimiento (último release, deprecación), si
  `SECAUDIT_ABANDONED_CHECK=1`.
- Las dependencias fantasma y el código muerto.
- Si no hay lockfile, se indica que solo se conocen las dependencias
  directas.

### Superficie de ataque

- Los puntos de entrada, con:
  - si se ve autenticación;
  - si se ve validación de la entrada;
  - qué tocan.
- Las fronteras de confianza.
- Los **servicios**: contenedores (puertos publicados, privileged), objetos
  Kubernetes, bases de datos, hosts externos y SDK de terceros.
- Los flujos de taint.
- Un «none_seen» es un sitio que mirar, no un hallazgo.

### Cambios

Qué hallazgos son nuevos, cuáles se corrigieron, cuáles persisten y cuáles
volvieron, frente a la base. También muestra:

- la deriva de seguridad: controles que el diff debilita;
- la historia del proyecto.

### Gemelo

Un mapa del sistema auditado: áreas, entradas, activos, servicios,
dependencias, hallazgos y atacantes, con sus relaciones.

- Cada nodo dice lo que **no se sabe** de él: ficheros sin leer, entradas sin
  autenticación vista, lenguajes sin inventariar, dependencias sin consultar.
- Es un mapa de lo medido, no una copia ejecutable.

## 3. Ajustes

Todo es opcional y está desactivado por defecto:

| Variable | Qué hace |
|---|---|
| `SECAUDIT_ALLOWED_REPO_OWNERS` | Propietarios de GitHub permitidos (separados por comas) |
| `SECAUDIT_OSV_CHECK=1` | Envía nombre, ecosistema y versión de los paquetes a OSV.dev |
| `SECAUDIT_ABANDONED_CHECK=1` | Pregunta a PyPI, npm y crates.io por el último release |
| `SECAUDIT_SCAN_TIMEOUT`, `SECAUDIT_SCAN_MEMORY_MB` | Límites del proceso que ejecuta los escáneres |
| `SECAUDIT_MAX_SCAN_CHARS`, `SECAUDIT_MAX_SCAN_FILES` | Cuánto leen los escáneres |

## 4. Sin servidor

```bash
python3 -m analysis.mcp_audit /ruta/al/repo        # auditoría MCP
python3 -m analysis.mcp_audit --check-taxonomy     # taxonomía OWASP MCP
python3 -m analysis.benchmark --corpus benchmark   # puntuar los escáneres
python3 -m analysis.benchmark etiquetas.json auditoria.json   # puntuar una auditoría
```

Ninguno de estos comandos ejecuta código del repositorio que lee.
