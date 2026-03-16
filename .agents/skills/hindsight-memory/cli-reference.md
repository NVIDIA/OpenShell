# Hindsight CLI Reference

## Installation

```bash
curl -fsSL https://hindsight.vectorize.io/get-cli | bash
```

## Configuration

```bash
# Interactive configuration
hindsight configure

# Or set directly
hindsight configure --api-url https://api.hindsight.vectorize.io

# Or use environment variables (highest priority)
export HINDSIGHT_API_URL=https://api.hindsight.vectorize.io
export HINDSIGHT_API_KEY=hs-your-api-key
```

Config file location: `~/.hindsight/config`

## Memory Commands

### retain — Store a Memory

```bash
hindsight memory retain <bank_id> "<text>"
hindsight memory retain <bank_id> "<text>" --context <tag>
hindsight memory retain <bank_id> "<text>" --async
```

| Flag | Description |
|------|-------------|
| `--context <tag>` | Context tag for categorization (e.g., learnings, procedures, conventions) |
| `--async` | Queue for background processing instead of waiting |

### retain-files — Bulk Import from Files

```bash
hindsight memory retain-files <bank_id> <file_or_directory>
hindsight memory retain-files <bank_id> <path> --context <tag>
hindsight memory retain-files <bank_id> <path> --async
```

| Flag | Description |
|------|-------------|
| `--context <tag>` | Context tag applied to all retained content |
| `--async` | Queue for background processing |

Directories are processed recursively by default.

### recall — Search Memories

```bash
hindsight memory recall <bank_id> "<query>"
hindsight memory recall <bank_id> "<query>" --budget high
hindsight memory recall <bank_id> "<query>" --max-tokens 8192
hindsight memory recall <bank_id> "<query>" --fact-type world,experience
hindsight memory recall <bank_id> "<query>" --trace
```

| Flag | Description |
|------|-------------|
| `--budget <level>` | Search thoroughness: low, medium, high (default: medium) |
| `--max-tokens <n>` | Maximum tokens in response |
| `--fact-type <types>` | Comma-separated: world, experience, observation |
| `--trace` | Show trace information for debugging |

### reflect — Synthesized Response

```bash
hindsight memory reflect <bank_id> "<question>"
hindsight memory reflect <bank_id> "<question>" --context <tag>
hindsight memory reflect <bank_id> "<question>" --budget high
```

| Flag | Description |
|------|-------------|
| `--context <tag>` | Additional context for the reflection |
| `--budget <level>` | Search thoroughness: low, medium, high |

## Bank Management

```bash
hindsight bank list                           # List all banks
hindsight bank stats <bank_id>                # View bank statistics
hindsight bank disposition <bank_id>          # View personality traits
hindsight bank name <bank_id> "<name>"        # Set bank display name
hindsight bank background <bank_id> "<text>"  # Set bank background context
```

## Document Management

```bash
hindsight document list <bank_id>                       # List documents
hindsight document get <bank_id> <document_id>          # Get document details
hindsight document delete <bank_id> <document_id>       # Delete document and memories
```

## Entity Management

```bash
hindsight entity list <bank_id>                              # List entities
hindsight entity get <bank_id> <entity_id>                   # Get entity details
hindsight entity regenerate <bank_id> <entity_id>            # Regenerate observations
```

## Output Formats

```bash
hindsight memory recall <bank_id> "query"              # Pretty (default)
hindsight memory recall <bank_id> "query" -o json      # JSON
hindsight memory recall <bank_id> "query" -o yaml      # YAML
```

## Global Flags

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Show detailed output including request/response |
| `-o, --output <format>` | Output format: pretty, json, yaml |
| `--help` | Show help |
| `--version` | Show version |

## API Endpoints

The Hindsight API exposes these endpoints (relevant for network policy authoring):

| Method | Path | Operation |
|--------|------|-----------|
| POST | `/v1/default/banks/{bank_id}/files/retain` | Retain files |
| POST | `/v1/default/banks/{bank_id}/memories/recall` | Recall memories |
| POST | `/v1/default/banks/{bank_id}/reflect` | Reflect on memories |
| GET | `/v1/default/banks` | List banks |
| GET | `/v1/default/banks/{bank_id}/stats` | Bank statistics |
| GET | `/v1/default/banks/{bank_id}/entities` | List entities |
| GET | `/v1/default/banks/{bank_id}/memories/list` | List memories |
| POST | `/v1/default/banks/{bank_id}/documents` | Upload documents |
