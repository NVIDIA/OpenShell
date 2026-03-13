# NVIDIA OpenShell Fern Documentation

This folder contains the Fern Docs configuration for NVIDIA OpenShell.

## Installation

```bash
npm install -g fern-api
# Or: npx fern-api --version
```

## Local Preview

```bash
cd fern/
fern docs dev
# Or from project root: fern docs dev --project ./fern
```

Docs available at `http://localhost:3000`.

## Folder Structure

```
fern/
├── docs.yml              # Global config (title, colors, versions)
├── fern.config.json      # Fern CLI config
├── versions/
│   └── v0.1.0.yml       # Navigation for v0.1.0
├── v0.1.0/
│   └── pages/            # MDX content for v0.1.0
├── scripts/              # Migration and conversion scripts
├── components/           # Custom React components (footer)
└── assets/               # Favicon, logos, images
```

## Migration Workflow

To migrate or update docs from `docs/` to Fern:

```bash
# 1. Copy docs to fern (run from repo root)
python3 fern/scripts/copy_docs_to_fern.py v0.1.0

# 2. Expand {include} directives (index)
python3 fern/scripts/expand_includes.py fern/v0.1.0/pages

# 3. Convert OpenShell-specific syntax ({doc} roles, {ref} roles)
python3 fern/scripts/convert_openshell_specific.py fern/v0.1.0/pages

# 4. Convert MyST to Fern MDX
python3 fern/scripts/convert_myst_to_fern.py fern/v0.1.0/pages

# 5. Add frontmatter
python3 fern/scripts/add_frontmatter.py fern/v0.1.0/pages

# 6. Update internal links
python3 fern/scripts/update_links.py fern/v0.1.0/pages

# 7. Remove duplicate H1s (when title matches frontmatter)
python3 fern/scripts/remove_duplicate_h1.py fern/v0.1.0/pages

# 8. Fix MyST frontmatter for Fern compatibility
python3 fern/scripts/fix_frontmatter.py fern/v0.1.0/pages

# 9. Validate
./fern/scripts/check_unconverted.sh fern/v0.1.0/pages
```

## MDX Components

```mdx
<Note>Informational note</Note>
<Tip>Helpful tip</Tip>
<Warning>Warning message</Warning>
<Info>Info callout</Info>

<Cards>
  <Card title="Title" href="/path">Description</Card>
</Cards>

<Tabs>
  <Tab title="Python">```python\ncode\n```</Tab>
</Tabs>

<Accordion title="Details">Collapsible content</Accordion>
```

## Deploying

```bash
fern generate --docs
fern docs deploy
```

## Useful Links

- [Fern Docs](https://buildwithfern.com/learn/docs)
- [MDX Components](https://buildwithfern.com/learn/docs/components)
- [Versioning Guide](https://buildwithfern.com/learn/docs/configuration/versions)
