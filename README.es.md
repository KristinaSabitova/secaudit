# secaudit

> [Read this in English](README.md)

CLI de auditoría de seguridad defensiva. Orquesta un LLM para auditar una
aplicación web contra una lista de verificación estándar y hace seguimiento
de los hallazgos entre ejecuciones.

## Requisitos

- Python 3.10+
- Uno de los backends soportados (ver más abajo)

## Instalación rápida

```bash
# 1. Instala el alias de shell `secaudit` (escribe una línea en ~/.zshrc o ~/.bashrc)
python3 ~/tools/secaudit/secaudit.py init

# 2. Recarga el shell
source ~/.zshrc   # o abre una terminal nueva

# 3. Registra tu primer proyecto (ejecuta desde dentro del directorio del proyecto)
cd ~/dev/miproyecto
secaudit projects add miproyecto

# 4. Audítalo
secaudit miproyecto --staged
```

`init` es idempotente: ejecutarlo dos veces no duplica el alias.

## Backends soportados

Selecciona un backend con `--backend` o configúralo de forma permanente en
`~/.secaudit/config.toml` (se crea automáticamente en la primera ejecución
con ejemplos comentados).

### claude-code (por defecto)

Usa el [Claude Code CLI](https://docs.claude.com) instalado localmente.

```bash
# No necesita configuración adicional si `claude` está en el PATH
secaudit . --staged
secaudit . --staged --backend claude-code
```

### anthropic-api

HTTP directo a la API de Anthropic. No necesita el CLI de Claude Code.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
secaudit . --staged --backend anthropic-api
```

`~/.secaudit/config.toml`:
```toml
backend = "anthropic-api"
model = "claude-sonnet-4-6"
```

### openai-api

```bash
export OPENAI_API_KEY=sk-...
secaudit . --staged --backend openai-api
```

`~/.secaudit/config.toml`:
```toml
backend = "openai-api"
model = "gpt-4o"
```

### ollama — local, sin coste, sin cuenta

La opción sin coste: ejecuta un modelo local via [Ollama](https://ollama.com).
Sin API key, sin datos enviados a terceros.

```bash
# 1. Instala Ollama: https://ollama.com/download
# 2. Descarga un modelo
ollama pull llama3          # o qwen2.5-coder, codellama, mistral…
# 3. Ejecuta
secaudit . --staged --backend ollama
```

`~/.secaudit/config.toml`:
```toml
backend = "ollama"
model = "llama3"
# ollama_url = "http://localhost:11434"   # valor por defecto
```

## Alias de proyectos

Registra nombres cortos para no tener que escribir rutas completas nunca más.

El alias no se adivina, hay que registrarlo primero. El flujo sería:

```bash
cd ~/stela      # o donde sea que vivas ese proyecto
secaudit projects add stela
```

Eso guarda `stela → /Users/sabitova/stela` (o la ruta que sea) en
`~/.secaudit/projects.json`. A partir de ahí, `secaudit stela` funciona
desde cualquier sitio, igual que con cualquier otro proyecto registrado.

Puedes comprobar en cualquier momento qué proyectos tienes registrados con:

```bash
secaudit projects list
```

Otras operaciones:

```bash
# Registrar una ruta explícita desde cualquier sitio (sin hacer cd primero)
secaudit projects add api ~/dev/miempresa/api

# Usar el alias en cualquier lugar donde se acepta una ruta
secaudit stela --staged
secaudit api --diff main --backend ollama

# Eliminar un alias
secaudit projects remove stela
```

Si el directorio no es un repositorio git, secaudit avisa y pide confirmación.
Usa `--force` para saltarte la pregunta:

```bash
secaudit projects add scratch /tmp/scratch --force
```

Los alias se guardan en `~/.secaudit/projects.json`.

## Modo one-shot (v1, compatible hacia atrás)

Auditoría completa, sin seguimiento de estado.

```bash
secaudit .                                    # audita + aplica correcciones críticas/altas
secaudit . --report-only                      # audita, solo informa (no modifica nada)
secaudit . --report-only -o informe.md        # guarda el informe en un archivo
secaudit . --stack "Django + Vue"             # indica el stack tecnológico
secaudit . --scope backend                    # solo backend
secaudit . --print-prompt                     # previsualiza el prompt, sin ejecutar
```

## Modo diferencial (v2)

Audita un subconjunto de archivos y hace seguimiento de hallazgos entre
ejecuciones. El estado se guarda en
`~/.secaudit/state/<project-id>.json` — **nunca dentro del árbol del proyecto**.

### Flujo diario

```bash
# Auditar solo los archivos staged (antes de hacer commit)
secaudit . --staged

# Auditar archivos cambiados respecto a una rama
secaudit . --diff main
secaudit . --diff origin/main

# Mostrar todos los hallazgos, no solo NEW + REGRESSED
secaudit . --staged --all

# Volcar los hallazgos clasificados como JSON
secaudit . --staged --json
```

Por defecto solo se muestran los hallazgos **NEW** y **REGRESSED**.
Usa `--all` para ver también PERSISTING y FIXED.

### Estados de un hallazgo

| Estado | Significado |
|--------|-------------|
| `new` | Visto por primera vez |
| `persisting` | Ya estaba en la ejecución anterior |
| `regressed` | Estaba corregido y ha vuelto |
| `fixed` | Estaba presente, ya no se detecta |
| `accepted` | Suprimido manualmente |

### Supresión

```bash
# Suprimir un hallazgo por su ID de 8 caracteres
secaudit suppress a1b2c3d4 --reason "falso positivo: el rate limiting está en el proxy"

# Suprimir desde un directorio de proyecto concreto
secaudit suppress a1b2c3d4 --reason "wontfix" --project /ruta/al/proyecto

# Listar los hallazgos suprimidos
secaudit . --show-suppressed
```

Los hallazgos aceptados (ACCEPTED) nunca vuelven a aparecer como NEW o REGRESSED.

### Baseline (para repos legacy)

Acepta todos los hallazgos actuales como punto de partida para que solo
se notifiquen regresiones futuras:

```bash
secaudit baseline .
secaudit baseline /ruta/al/proyecto
```

## Notas de seguridad

- Los archivos de estado viven en `~/.secaudit/` — nunca se escriben dentro
  del repo auditado.
- Las API keys se leen de variables de entorno y **nunca** se registran,
  almacenan en el estado ni se imprimen en ninguna salida.
- Para los hallazgos de la categoría `secrets`, los valores secretos se
  **redactan** antes de almacenarse y mostrarse. Solo se conservan el tipo,
  la ruta del archivo y un hash corto de 6 caracteres.
- `.gitignore` excluye `.secaudit/`, `*.secaudit.json`, `.env*`.

## Ejecutar los tests

```bash
python3 -m pytest tests/ -v
```
